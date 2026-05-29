package vaguebot

import (
	"context"
	"errors"
	"fmt"
	"image/png"
	"log"
	neturl "net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
	pb "vague-bot/proto"

	"github.com/mdp/qrterminal/v3"
	qrcode "github.com/skip2/go-qrcode"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const selfbotLoginAppName = "WEB-APP"
const selfbotDefaultLoginBaseURL = "https://link.vague-infinity.com"

func normalizeDeviceLoginBaseURL(raw string) string {
	base := strings.TrimSpace(raw)
	if base == "" {
		return ""
	}
	base = strings.TrimRight(base, "/")
	lower := strings.ToLower(base)
	if strings.HasSuffix(lower, "/login") {
		base = strings.TrimRight(base[:len(base)-len("/login")], "/")
	}
	return base
}

func normalizeDeviceLoginLink(loginLink, requestCode string) string {
	loginLink = strings.TrimSpace(loginLink)
	requestCode = strings.TrimSpace(requestCode)
	if loginLink == "" && requestCode == "" {
		return ""
	}
	if strings.HasPrefix(loginLink, "http://") || strings.HasPrefix(loginLink, "https://") {
		return loginLink
	}
	if requestCode == "" && strings.HasPrefix(loginLink, "vaguechat://login/") {
		requestCode = strings.TrimSpace(strings.TrimPrefix(loginLink, "vaguechat://login/"))
	}
	if requestCode == "" {
		return loginLink
	}
	return fmt.Sprintf("%s/loginqr/%s", selfbotDefaultLoginBaseURL, neturl.PathEscape(requestCode))
}

func (c *Client) CreateDeviceLoginLink(deviceName, appName string) (*pb.CreateDeviceLoginLinkResponse, error) {
	if c == nil || c.GrpcClient == nil {
		return nil, errors.New("grpc client is not ready")
	}
	deviceName = strings.TrimSpace(deviceName)
	if deviceName == "" {
		deviceName = "brainwave-selfbot"
	}
	appName = strings.TrimSpace(appName)
	if appName == "" {
		appName = selfbotLoginAppName
	}

	callCtx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	resp, err := c.GrpcClient.CreateDeviceLoginLink(callCtx, &pb.CreateDeviceLoginLinkRequest{
		DeviceName: deviceName,
		AppName:    appName,
	})
	if err != nil {
		return nil, fmt.Errorf("CreateDeviceLoginLink rpc: %w", err)
	}
	if err := statusErr("CreateDeviceLoginLink", resp.GetStatus(), resp.GetResponseMessage()); err != nil {
		return nil, err
	}
	return resp, nil
}

func (c *Client) LoginSecondaryDevice(deviceName string) (*pb.LoginSecondaryDeviceResponse, error) {
	if c == nil || c.GrpcClient == nil {
		return nil, errors.New("grpc client is not ready")
	}
	deviceName = strings.TrimSpace(deviceName)
	if deviceName == "" {
		deviceName = "vague-selfbot"
	}

	callCtx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	resp, err := c.GrpcClient.LoginSecondaryDevice(callCtx, &pb.LoginSecondaryDeviceRequest{
		DeviceName: deviceName,
	})
	if err != nil {
		return nil, fmt.Errorf("LoginSecondaryDevice rpc: %w", err)
	}
	if err := statusErr("LoginSecondaryDevice", resp.GetStatus(), resp.GetResponseMessage()); err != nil {
		return nil, err
	}
	return resp, nil
}

type deviceLoginTicket struct {
	requestCode string
	pollToken   string
	loginLink   string
	expiresAt   int64
}

func (c *Client) createSecondaryDeviceLoginTicket(deviceName string) (*deviceLoginTicket, error) {
	resp, err := c.LoginSecondaryDevice(deviceName)
	if err == nil {
		return &deviceLoginTicket{
			requestCode: strings.TrimSpace(resp.GetRequestCode()),
			pollToken:   strings.TrimSpace(resp.GetPollToken()),
			loginLink:   strings.TrimSpace(resp.GetLoginLink()),
			expiresAt:   resp.GetExpiresAt(),
		}, nil
	}
	if status.Code(err) != codes.Unimplemented {
		return nil, err
	}

	legacyResp, legacyErr := c.CreateDeviceLoginLink(deviceName, selfbotLoginAppName)
	if legacyErr != nil {
		return nil, fmt.Errorf("LoginSecondaryDevice unavailable and CreateDeviceLoginLink fallback failed: %w", legacyErr)
	}
	return &deviceLoginTicket{
		requestCode: strings.TrimSpace(legacyResp.GetRequestCode()),
		pollToken:   strings.TrimSpace(legacyResp.GetPollToken()),
		loginLink:   strings.TrimSpace(legacyResp.GetLoginLink()),
		expiresAt:   legacyResp.GetExpiresAt(),
	}, nil
}

func (c *Client) PollDeviceLoginLink(requestCode, pollToken string) (*pb.PollDeviceLoginLinkResponse, error) {
	if c == nil || c.GrpcClient == nil {
		return nil, errors.New("grpc client is not ready")
	}
	requestCode = strings.TrimSpace(requestCode)
	pollToken = strings.TrimSpace(pollToken)
	if requestCode == "" || pollToken == "" {
		return nil, errors.New("request code and poll token are required")
	}

	callCtx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	resp, err := c.GrpcClient.PollDeviceLoginLink(callCtx, &pb.PollDeviceLoginLinkRequest{
		RequestCode: requestCode,
		PollToken:   pollToken,
	})
	if err != nil {
		return nil, fmt.Errorf("PollDeviceLoginLink rpc: %w", err)
	}
	return resp, nil
}

func beginSelfbotLoginQRCodePath(requestCode string) string {
	requestCode = strings.ReplaceAll(strings.TrimSpace(requestCode), "/", "_")
	sender := "unknown"
	if requestCode == "" {
		requestCode = fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return filepath.Join(".", "tmp", fmt.Sprintf("selfbot-login-%s-%s", sender, requestCode))
}

func CreateQRImage(query string) {
	//err := qrcode.WriteColorFile("https://example.org", qrcode.Medium, 256, color.Black, color.White, "qr.png")
	qr, err := qrcode.New(query, qrcode.Medium)
	if err != nil {
		fmt.Println(err)
	}
	_, su := os.Stat("./tmp/")
	if os.IsNotExist(su) {
		errDir := os.MkdirAll("./tmp/", 0755)
		if errDir != nil {
			fmt.Println(su)
		}
	}
	file, err := os.Create("./tmp/" + "vague" + ".png")
	if err != nil {
		fmt.Println(err)
	}
	defer file.Close()
	err = png.Encode(file, qr.Image(500))
	if err != nil {
		fmt.Println(err)
	}
}

func SelfbotLogin() (*Client, error) {
	loginClient, err := CreateClient(context.Background(), AccountRecord{}, LoadConfig(), nil)
	if loginClient == nil || loginClient.GrpcClient == nil {
		return nil, errors.New("device login link service is unavailable")
	}
	defer func() {
		if loginClient.GrpcConn != nil {
			_ = loginClient.GrpcConn.Close()
		}
	}()

	ticket, err := loginClient.createSecondaryDeviceLoginTicket("vague-selfbot")
	if err != nil {
		return nil, err
	}
	loginLink := normalizeDeviceLoginLink(ticket.loginLink, ticket.requestCode)
	if loginLink == "" {
		return nil, errors.New("device login link is empty")
	}

	log.Printf("Generated selfbot login ticket. RequestCode: %s, PollToken: %s, LoginLink: %s, ExpiresAt: %d", ticket.requestCode, ticket.pollToken, loginLink, ticket.expiresAt)
	config := qrterminal.Config{
		Level:     qrterminal.L,
		Writer:    os.Stdout,
		BlackChar: qrterminal.BLACK,
		WhiteChar: qrterminal.WHITE,
		QuietZone: 1,
	}
	qrterminal.GenerateWithConfig(loginLink, config)
	cl := loginClient.awaitSelfbotLogin(ticket.requestCode, ticket.pollToken, ticket.expiresAt)
	return cl, nil
}

func isPendingDeviceLogin(status pb.RequestStatus, state string) bool {
	state = strings.ToLower(strings.TrimSpace(state))
	if status == pb.RequestStatus_SUCCESS {
		return state == "" || state == "pending" || state == "waiting" || state == "scanned" || state == "approved"
	}
	return status == pb.RequestStatus_NOT_READY
}

func isRejectedDeviceLogin(state string) bool {
	switch strings.ToLower(strings.TrimSpace(state)) {
	case "rejected", "denied", "canceled", "cancelled", "expired":
		return true
	default:
		return false
	}
}

func (client *Client) awaitSelfbotLogin(requestCode, pollToken string, expiresAt int64) *Client {
	pollClient, _ := CreateClient(context.Background(), AccountRecord{}, LoadConfig(), nil)
	if pollClient == nil || pollClient.GrpcClient == nil {
		log.Println("Selfbot login polling failed: grpc client is unavailable.")
		return nil
	}
	defer func() {
		if pollClient.GrpcConn != nil {
			_ = pollClient.GrpcConn.Close()
		}
	}()

	deadline := time.Now().Add(2 * time.Minute)
	if expiresAt > 0 {
		deadline = time.UnixMilli(expiresAt)
	}

	for time.Now().Before(deadline.Add(3 * time.Second)) {
		resp, err := pollClient.PollDeviceLoginLink(requestCode, pollToken)
		if err != nil {
			log.Panicln("Selfbot login failed while polling approval.\n\n" + err.Error())
			return nil
		}

		state := strings.TrimSpace(resp.GetState())
		status := resp.GetStatus()
		token := strings.TrimSpace(resp.GetToken())
		refreshToken := strings.TrimSpace(resp.GetRefreshToken())

		if token != "" {
			cid := strings.TrimSpace(resp.GetUserId())
			cl := client.finishSelfbotLogin(cid, strings.TrimSpace(resp.GetUsername()), token, refreshToken)
			if cl == nil {
				log.Panicln("Selfbot login approval received, but activation failed.")
			}
			return cl
		}

		switch {
		case isPendingDeviceLogin(status, state):
			time.Sleep(3 * time.Second)
			continue
		case status == pb.RequestStatus_ALREADY_EXPIRED || isRejectedDeviceLogin(state):
			log.Println("Selfbot login request expired or was rejected.")
			return nil
		default:
			log.Println(fmt.Sprintf("Selfbot login failed.\n\nState: %s\nStatus: %s\nMessage: %s", state, status.String(), resp.GetResponseMessage()))
			return nil
		}
	}

	log.Println("Selfbot login timed out before approval completed.")
	return nil
}

func (client *Client) finishSelfbotLogin(cid, username, token, refreshToken string) *Client {
	token = strings.TrimSpace(token)
	refreshToken = strings.TrimSpace(refreshToken)
	if token == "" {
		log.Println("token nil")
		return nil
	}

	authClient, _ := CreateClient(context.Background(), AccountRecord{CID: cid, Token: token, RefreshToken: refreshToken}, LoadConfig(), nil)
	if authClient == nil || authClient.GrpcClient == nil {
		log.Printf("Failed to create authenticated client with selfbot token. CID: %s", cid)
		return nil
	}

	profile, err := authClient.GetProfile(context.TODO())
	if err != nil {
		log.Printf("Failed to get profile with new selfbot token: %v", err)
		return nil
	}

	if strings.TrimSpace(profile.GetCid()) != "" {
		cid = strings.TrimSpace(profile.GetCid())
	}
	if strings.TrimSpace(profile.GetDisplayName()) != "" {
		username = strings.TrimSpace(profile.GetDisplayName())
	}

	// Save credentials to account.json
	cfg := LoadConfig()
	store, err := NewAccountStore(cfg.AccountFile)
	if err == nil {
		account := AccountRecord{
			CID:          cid,
			Token:        token,
			RefreshToken: refreshToken,
			DeviceID:     authClient.deviceID,
			E2EEPublic:   authClient.e2eePublicB64,
			E2EEPrivate:  authClient.e2eePrivateB64,
		}
		if err := store.UpsertSelfbot(account); err != nil {
			log.Printf("Failed to save selfbot credentials: %v", err)
		} else {
			SetSelfbotCIDs(store.AccountsSelfbot())
			log.Printf("Selfbot credentials saved to %s", cfg.AccountFile)
		}
	}

	sessionInfo := ""
	if sessions, sessErr := authClient.ListSessions(); sessErr == nil {
		sessionInfo = fmt.Sprintf("\nActive sessions: %d", len(sessions))
	}
	log.Printf("Selfbot login successful! CID: %s, Username: %s.%s", cid, username, sessionInfo)

	if username == "" {
		username = cid
	}
	return authClient
}

func (c *Client) ListSessions() ([]*pb.Session, error) {
	if c == nil || c.GrpcClient == nil {
		return nil, errors.New("grpc client is not ready")
	}

	callCtx, cancel := context.WithTimeout(context.TODO(), 20*time.Second)
	defer cancel()

	resp, err := c.GrpcClient.ListSessions(callCtx, &pb.ListSessionsRequest{})
	if err != nil {
		return nil, fmt.Errorf("ListSessions rpc: %w", err)
	}
	if err := statusErr("ListSessions", resp.GetStatus(), resp.GetResponseMessage()); err != nil {
		return nil, err
	}
	return resp.GetSessions(), nil
}
