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
	cfg := vaguebot.LoadConfig()

	store, err := vaguebot.NewAccountStore(cfg.AccountFile)
	if err != nil {
		log.Fatalf("failed init account store: %v", err)
	}

	accounts := store.Accounts()
	if len(accounts) == 0 {
		log.Fatalf("no accounts found in %s", cfg.AccountFile)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	clients := make([]*vaguebot.Client, 0, len(accounts))
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
	}

	if len(clients) == 0 {
		log.Fatalf("no bot client can be started (all accounts failed)")
	}

	vaguebot.SetPeerClients(clients)
	log.Printf("running %d bot client(s) on %s using %s", len(clients), cfg.Target, cfg.AccountFile)

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

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		err := client.ChatStreamMultiEvent(ctx)
		if err == nil {
			backoff = 2 * time.Second
			continue
		}
		if ctx.Err() != nil || errors.Is(err, context.Canceled) {
			return
		}
		if status.Code(err) == codes.Unauthenticated {
			log.Printf("[%s] stream stopped (unauthenticated): %v", client.CurrentCID(), err)
			return
		}

		log.Printf("[%s] stream error: %v (retry in %s)", client.CurrentCID(), err, backoff)
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
