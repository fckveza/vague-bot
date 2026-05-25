package main

import (
	"context"
	"errors"
	"log"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"vague-bot/vaguebot"
)

func main() {
	vaguebot.Selfbot = true
	var clients []*vaguebot.Client
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if vaguebot.Selfbot {
		cfg := vaguebot.LoadConfig()
		store, err := vaguebot.NewAccountStore(cfg.AccountFile)
		if err != nil {
			log.Fatalf("failed init account store: %v", err)
		}

		accounts := store.AccountsSelfbot()
		log.Printf("Selfbot: found %d saved accounts", len(accounts))
		if len(accounts) > 0 {
			// Use existing selfbot account
			account := accounts[0]
			log.Printf("Selfbot: trying saved account cid=%s token_len=%d", account.CID, len(account.Token))
			client, err := vaguebot.CreateClient(ctx, account, cfg, store.Upsert)
			if err != nil {
				log.Printf("failed to create client from saved account: %v", err)
				log.Println("Trying fresh login...")
				client = nil
			} else {
				profile, err := client.GetProfile(ctx)
				if err != nil {
					log.Printf("GetProfile failed, trying refresh: %v", err)
					res, err := client.RefreshAuthToken(ctx, client.RefreshToken)
					if err != nil {
						log.Printf("failed to refresh auth token: %v", err)
						log.Println("Trying fresh login...")
						_ = client.Close()
						client = nil
					} else {
						client.Token = res.GetToken()
						client.RefreshToken = res.GetRefreshToken()
						log.Printf("refreshed auth token for cid=%s", client.CID)
					}
				}
				if profile != nil {
					log.Printf("Loaded saved selfbot account: cid=%s display_name=%s", profile.GetCid(), profile.GetDisplayName())
				}
			}
			if client != nil {
				clients = []*vaguebot.Client{client}
			}
		}

		if len(clients) == 0 {
			// No saved account or login failed - do fresh QR login
			log.Println("Selfbot: No valid saved account, showing QR code...")
			client, err := vaguebot.SelfbotLogin()
			if err != nil || client == nil {
				log.Fatalf("selfbot login failed")
			}
			clients = []*vaguebot.Client{client}
			log.Printf("running selfbot client on device login")
		}
		ress, err := clients[0].GetLastEventRevision(ctx)
		if err != nil {
			log.Panicf("failed to get last event revision for cid=%s: %v", clients[0].CID, err)
		} else {
			clients[0].Revision = ress.GetCurrentRevision()
			log.Println(clients[0].Revision)
		}
	} else {
		cfg := vaguebot.LoadConfig()

		store, err := vaguebot.NewAccountStore(cfg.AccountFile)
		if err != nil {
			log.Fatalf("failed init account store: %v", err)
		}

		accounts := store.Accounts()
		if len(accounts) == 0 {
			log.Fatalf("no accounts found in %s", cfg.AccountFile)
		}

		clients = make([]*vaguebot.Client, 0, len(accounts))
		for _, account := range accounts {
			client, err := vaguebot.CreateClient(ctx, account, cfg, store.Upsert)
			if err != nil {
				log.Printf("skip account cid=%s email=%s: %v", account.CID, account.Email, err)
				continue
			}

			profile, err := client.GetProfile(ctx)
			if err != nil {
				res, err := client.RefreshAuthToken(ctx, client.RefreshToken)
				if err != nil {
					log.Printf("failed to refresh auth token for cid=%s email=%s: %v", account.CID, account.Email, err)
					_ = client.Close()
					continue
				} else {
					client.Token = res.GetToken()
					client.RefreshToken = res.GetRefreshToken()
					log.Printf("refreshed auth token for cid=%s email=%s", account.CID, account.Email)
				}
			}
			if profile != nil {
				log.Printf("bot active cid=%s display_name=%s", profile.GetCid(), profile.GetDisplayName())
			} else {
				log.Printf("bot active cid=%s", client.CurrentCID())
			}

			if err := client.EnsureE2EEIdentity(ctx); err != nil {
				log.Printf("failed init e2ee key for cid=%s: %v", client.CurrentCID(), err)
				_ = client.Close()
				continue
			}

			if err := client.AcceptAllPendingInvitations(ctx); err != nil {
				log.Printf("[%s] failed accepting invitations: %v", client.CurrentCID(), err)
			}
			_ = client.PersistState()
			clients = append(clients, client)
			ress, err := client.GetLastEventRevision(ctx)
			if err != nil {
				log.Printf("failed to get last event revision for cid=%s: %v", client.CID, err)
			} else {
				client.Revision = ress.GetCurrentRevision()
				log.Println(client.Revision)
			}
		}
		log.Printf("running %d bot client(s) on %s using %s", len(clients), cfg.Target, cfg.AccountFile)
	}

	if len(clients) == 0 {
		log.Fatalf("no bot client can be started (all accounts failed)")
	}

	vaguebot.SetPeerClients(clients)

	// Add all clients to Squad and Mclient
	for _, client := range clients {
		vaguebot.Squad = append(vaguebot.Squad, client.CID)
		vaguebot.Mclient[client.CID] = client
	}

	var wg sync.WaitGroup
	for _, client := range clients {
		client := client
		wg.Add(1)
		go func() {
			defer wg.Done()
			runClientLoop(ctx, client)
		}()
	}

	<-ctx.Done()
	log.Printf("shutdown signal received")

	for _, client := range clients {
		_ = client.PersistState()
		_ = client.Close()
	}
	wg.Wait()
}

func runClientLoop(ctx context.Context, client *vaguebot.Client) {
	backoff := 2 * time.Second
	cycle := 0

	for {
		select {
		case <-ctx.Done():
			log.Printf("[%s] stream loop stop: context canceled", client.CurrentCID())
			return
		default:
		}

		cycle++
		log.Printf(
			"[%s] stream cycle start cycle=%d revision=%d backoff=%s",
			client.CurrentCID(),
			cycle,
			client.Revision,
			backoff,
		)
		err := client.ChatStreamMultiEvent(ctx)
		if err == nil {
			log.Printf(
				"[%s] stream cycle end clean cycle=%d (EOF/normal close), reconnect immediately",
				client.CurrentCID(),
				cycle,
			)
			backoff = 2 * time.Second
			continue
		}
		if ctx.Err() != nil || errors.Is(err, context.Canceled) {
			log.Printf("[%s] stream cycle canceled cycle=%d err=%v", client.CurrentCID(), cycle, err)
			return
		}
		if status.Code(err) == codes.Unauthenticated {
			log.Printf("[%s] stream stopped (unauthenticated): %v", client.CurrentCID(), err)
			return
		}

		log.Printf(
			"[%s] stream error cycle=%d code=%s err=%v (retry in %s)",
			client.CurrentCID(),
			cycle,
			status.Code(err),
			err,
			backoff,
		)
		_ = client.PersistState()

		timer := time.NewTimer(backoff)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}

		if backoff < 30*time.Second {
			backoff *= 2
			if backoff > 30*time.Second {
				backoff = 30 * time.Second
			}
		}
	}
}
