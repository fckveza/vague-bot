package vaguebot

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"mime"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	pb "vague-bot/proto"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/metadata"
)

type PersistAccountFunc func(AccountRecord) error

type recipientBundleKey struct {
	DeviceID     string `json:"device_id"`
	KeyID        int32  `json:"key_id"`
	PublicKeyB64 string `json:"public_key_b64"`
}

type recipientFanoutEnvelope struct {
	DeviceID           string `json:"device_id,omitempty"`
	KeyID              int32  `json:"key_id"`
	EphemeralPublicKey string `json:"ephemeral_public_key"`
	IV                 string `json:"iv"`
	Ciphertext         string `json:"ciphertext"`
	MAC                string `json:"mac"`
}

type groupPublicKeyEnvelope struct {
	CurrentPublicKeyB64 string `json:"current_public_key_b64"`
	PublicKeyB64        string `json:"public_key_b64"`
}

func decodeGroupPublicKeyPayload(raw []byte) ([]byte, error) {
	if len(raw) == 32 {
		return cloneBytes(raw), nil
	}
	if len(raw) == 0 {
		return nil, errors.New("group shared key payload is empty")
	}

	var payload groupPublicKeyEnvelope
	if err := json.Unmarshal(raw, &payload); err != nil {
		return nil, errors.New("invalid group shared key format")
	}

	keyB64 := strings.TrimSpace(payload.CurrentPublicKeyB64)
	if keyB64 == "" {
		keyB64 = strings.TrimSpace(payload.PublicKeyB64)
	}
	key, err := base64.StdEncoding.DecodeString(keyB64)
	if err != nil || len(key) != 32 {
		return nil, errors.New("invalid group shared key format")
	}
	return key, nil
}

type UploadedMedia struct {
	URL      string
	FileName string
	MIMEType string
	Size     int64
}

var (
	peerClientsMu sync.RWMutex
	peerClients   []*Client
)

type Client struct {
	CID          string
	Token        string
	RefreshToken string
	Revision     int64

	GrpcConn   *grpc.ClientConn
	GrpcClient pb.VagueServiceClient

	deviceID string
	cfg      Config
	persist  PersistAccountFunc

	e2eePublicB64  string
	e2eePrivateB64 string

	mu              sync.RWMutex
	handledMessages map[string]struct{}
	messageOrder    []string
	recipientPK     map[string][]byte
	groupPK         map[string][]byte
	lastE2EEReg     time.Time
}

func SetPeerClients(clients []*Client) {
	peerClientsMu.Lock()
	defer peerClientsMu.Unlock()
	peerClients = append(make([]*Client, 0, len(clients)), clients...)
}

func snapshotPeerClients() []*Client {
	peerClientsMu.RLock()
	defer peerClientsMu.RUnlock()
	return append(make([]*Client, 0, len(peerClients)), peerClients...)
}

func CreateClient(ctx context.Context, account AccountRecord, cfg Config, persist PersistAccountFunc) (*Client, error) {
	//router := NewEventRouter()
	client := &Client{
		CID:          strings.TrimSpace(account.CID),
		Token:        strings.TrimSpace(account.Token),
		RefreshToken: strings.TrimSpace(account.RefreshToken),
		Revision:     account.Revision,
		deviceID:     chooseDeviceID(account),
		cfg:          cfg,
		persist:      persist,
		//router:          router,
		e2eePublicB64:   strings.TrimSpace(account.E2EEPublic),
		e2eePrivateB64:  strings.TrimSpace(account.E2EEPrivate),
		handledMessages: make(map[string]struct{}),
		messageOrder:    make([]string, 0, 256),
		recipientPK:     make(map[string][]byte),
		groupPK:         make(map[string][]byte),
	}
	//client.registerDefaultHandlers()

	dialCtx, cancel := context.WithTimeout(ctx, cfg.UnaryTimeout)
	defer cancel()

	conn, err := grpc.DialContext(
		dialCtx,
		cfg.Target,
		grpc.WithTransportCredentials(client.transportCredentials()),
		grpc.WithKeepaliveParams(keepalive.ClientParameters{
			Time:                60 * time.Second,
			Timeout:             10 * time.Second,
			PermitWithoutStream: true,
		}),
		grpc.WithDefaultCallOptions(
			grpc.MaxCallRecvMsgSize(120*1024*1024),
			grpc.MaxCallSendMsgSize(120*1024*1024),
		),
		grpc.WithUnaryInterceptor(client.unaryAuthInterceptor()),
		grpc.WithStreamInterceptor(client.streamAuthInterceptor()),
	)
	if err != nil {
		return nil, fmt.Errorf("dial grpc %s: %w", cfg.Target, err)
	}

	client.GrpcConn = conn
	client.GrpcClient = pb.NewVagueServiceClient(conn)
	ress, err := client.GetLastEventRevision(ctx)
	if err != nil {
		log.Printf("failed to get last event revision for cid=%s: %v", client.CID, err)
	} else {
		client.Revision = ress.GetCurrentRevision()
		log.Println(client.Revision)
	}
	return client, nil
}

func chooseDeviceID(account AccountRecord) string {
	if account.DeviceID != "" {
		return account.DeviceID
	}
	if account.CID != "" {
		return account.CID
	}
	if account.Email != "" {
		return "vague-bot-" + strings.ReplaceAll(account.Email, "@", "-")
	}
	return fmt.Sprintf("vague-bot-%d", time.Now().UnixNano())
}

func (c *Client) transportCredentials() credentials.TransportCredentials {
	if c.cfg.Insecure || !shouldUseTLS(c.cfg.Target) {
		return insecure.NewCredentials()
	}
	return credentials.NewTLS(&tls.Config{MinVersion: tls.VersionTLS12})
}

func shouldUseTLS(target string) bool {
	normalized := strings.TrimSpace(target)
	normalized = strings.TrimPrefix(normalized, "dns://")
	normalized = strings.TrimPrefix(normalized, "http://")
	normalized = strings.TrimPrefix(normalized, "https://")

	hostPort := normalized
	if slash := strings.Index(hostPort, "/"); slash >= 0 {
		hostPort = hostPort[:slash]
	}

	host := hostPort
	port := ""
	if strings.HasPrefix(hostPort, "[") {
		if idx := strings.Index(hostPort, "]"); idx >= 0 {
			host = hostPort[1:idx]
			if idx+2 <= len(hostPort) && hostPort[idx+1] == ':' {
				port = hostPort[idx+2:]
			}
		}
	} else if idx := strings.LastIndex(hostPort, ":"); idx >= 0 {
		host = hostPort[:idx]
		port = hostPort[idx+1:]
	}

	if port == "443" {
		return true
	}
	switch host {
	case "localhost", "127.0.0.1", "0.0.0.0", "::1":
		return false
	}
	if strings.HasPrefix(host, "127.") {
		return false
	}
	return true
}

func (c *Client) Close() error {
	if c.GrpcConn == nil {
		return nil
	}
	return c.GrpcConn.Close()
}

func (c *Client) unaryAuthInterceptor() grpc.UnaryClientInterceptor {
	return func(
		ctx context.Context,
		method string,
		req interface{},
		reply interface{},
		cc *grpc.ClientConn,
		invoker grpc.UnaryInvoker,
		opts ...grpc.CallOption,
	) error {
		ctx = metadata.NewOutgoingContext(ctx, c.outgoingMetadata())
		var header metadata.MD
		opts = append(opts, grpc.Header(&header))
		err := invoker(ctx, method, req, reply, cc, opts...)
		c.captureNewToken(header)
		return err
	}
}

func (c *Client) streamAuthInterceptor() grpc.StreamClientInterceptor {
	return func(
		ctx context.Context,
		desc *grpc.StreamDesc,
		cc *grpc.ClientConn,
		method string,
		streamer grpc.Streamer,
		opts ...grpc.CallOption,
	) (grpc.ClientStream, error) {
		ctx = metadata.NewOutgoingContext(ctx, c.outgoingMetadata())
		return streamer(ctx, desc, cc, method, opts...)
	}
}

func (c *Client) outgoingMetadata() metadata.MD {
	c.mu.RLock()
	token := c.Token
	refresh := c.RefreshToken
	deviceID := c.deviceID
	c.mu.RUnlock()

	md := metadata.Pairs(
		"app-version", c.cfg.AppVersion,
		"app-build", c.cfg.AppBuild,
		"app-revision", c.cfg.AppRevision,
		"app-name", c.cfg.AppName,
		"device-id", deviceID,
		"device-type", c.cfg.DeviceType,
	)
	if token != "" {
		if strings.HasPrefix(strings.ToLower(token), "bearer ") {
			md.Append("authorization", token)
		} else {
			md.Append("authorization", "Bearer "+token)
		}
	}
	if refresh != "" {
		md.Append("x-refresh-token", refresh)
	}
	return md
}

func (c *Client) captureNewToken(header metadata.MD) {
	if header == nil {
		return
	}
	values := header.Get("x-new-token")
	if len(values) == 0 {
		return
	}

	token := strings.TrimSpace(values[0])
	if token == "" {
		return
	}

	c.mu.Lock()
	changed := c.Token != token
	if changed {
		c.Token = token
	}
	c.mu.Unlock()

	if changed {
		_ = c.PersistState()
	}
}

func (c *Client) setCID(cid string) {
	cid = strings.TrimSpace(cid)
	if cid == "" {
		return
	}
	c.mu.Lock()
	changed := c.CID != cid
	if changed {
		c.CID = cid
	}
	c.mu.Unlock()
	if changed {
		_ = c.PersistState()
	}
}

func (c *Client) maxRevision(revision int64) {
	if revision <= 0 {
		return
	}
	c.mu.Lock()
	if revision > c.Revision {
		c.Revision = revision
	}
	c.mu.Unlock()
}

func (c *Client) currentRevision() int64 {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.Revision < 0 {
		return 0
	}
	return c.Revision
}

func (c *Client) CurrentCID() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.CID
}

func (c *Client) snapshot() AccountRecord {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return AccountRecord{
		CID:          c.CID,
		Token:        c.Token,
		RefreshToken: c.RefreshToken,
		Revision:     c.Revision,
		DeviceID:     c.deviceID,
		E2EEPublic:   c.e2eePublicB64,
		E2EEPrivate:  c.e2eePrivateB64,
	}
}

func (c *Client) PersistState() error {
	if c.persist == nil {
		return nil
	}
	return c.persist(c.snapshot())
}

func statusErr(rpc string, status pb.RequestStatus, message string) error {
	if status == pb.RequestStatus_SUCCESS {
		return nil
	}
	if strings.TrimSpace(message) == "" {
		message = status.String()
	}
	return fmt.Errorf("%s failed: status=%s message=%s", rpc, status.String(), message)
}

func (c *Client) unaryContext(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, c.cfg.UnaryTimeout)
}

func cloneBytes(input []byte) []byte {
	if len(input) == 0 {
		return nil
	}
	out := make([]byte, len(input))
	copy(out, input)
	return out
}

func cloneStringMap(input map[string]string) map[string]string {
	if len(input) == 0 {
		return nil
	}
	out := make(map[string]string, len(input))
	for key, value := range input {
		out[key] = value
	}
	return out
}

func messageTypeFromTarget(target string) pb.MessageType {
	normalized := strings.ToLower(strings.TrimSpace(target))
	if strings.HasPrefix(normalized, "c") || strings.HasPrefix(normalized, "g") || strings.HasPrefix(normalized, "r") {
		return pb.MessageType_MessageType_Group
	}
	return pb.MessageType_MessageType_Private
}

func (c *Client) ensureLocalE2EEKeyPair() (publicKey []byte, privateKey []byte, changed bool, err error) {
	c.mu.RLock()
	currentPublic := c.e2eePublicB64
	currentPrivate := c.e2eePrivateB64
	c.mu.RUnlock()

	if currentPublic != "" && currentPrivate != "" {
		publicRaw, pubErr := base64.StdEncoding.DecodeString(currentPublic)
		privateRaw, privErr := base64.StdEncoding.DecodeString(currentPrivate)
		if pubErr == nil && privErr == nil && len(publicRaw) == 32 && len(privateRaw) == 32 {
			return publicRaw, privateRaw, false, nil
		}
	}

	publicRaw, privateRaw, genErr := generateX25519KeyPairRaw()
	if genErr != nil {
		return nil, nil, false, genErr
	}
	nextPublic := base64.StdEncoding.EncodeToString(publicRaw)
	nextPrivate := base64.StdEncoding.EncodeToString(privateRaw)

	c.mu.Lock()
	c.e2eePublicB64 = nextPublic
	c.e2eePrivateB64 = nextPrivate
	c.mu.Unlock()
	return publicRaw, privateRaw, true, nil
}

func (c *Client) localPrivateKeyRaw() ([]byte, error) {
	_, privateRaw, _, err := c.ensureLocalE2EEKeyPair()
	if err != nil {
		return nil, err
	}
	return privateRaw, nil
}

func (c *Client) EnsureE2EEIdentity(ctx context.Context) error {
	publicRaw, _, changed, err := c.ensureLocalE2EEKeyPair()
	if err != nil {
		return fmt.Errorf("ensure local e2ee key pair: %w", err)
	}
	if changed {
		if saveErr := c.PersistState(); saveErr != nil {
			log.Printf("[%s] failed persist generated e2ee key: %v", c.CurrentCID(), saveErr)
		}
	}

	c.mu.RLock()
	lastRegister := c.lastE2EEReg
	c.mu.RUnlock()
	if !lastRegister.IsZero() && time.Since(lastRegister) < 10*time.Minute {
		return nil
	}

	if err := c.RegisterPublicKey(ctx, publicRaw); err != nil {
		return err
	}

	c.mu.Lock()
	c.lastE2EEReg = time.Now()
	c.mu.Unlock()
	return nil
}

func (c *Client) RegisterPublicKey(ctx context.Context, key []byte) error {
	callCtx, cancel := c.unaryContext(ctx)
	defer cancel()

	resp, err := c.GrpcClient.RegisterPublicKey(callCtx, &pb.RegisterPublicKeyRequest{PublicKey: key})
	if err != nil {
		return fmt.Errorf("RegisterPublicKey rpc: %w", err)
	}
	return statusErr("RegisterPublicKey", resp.GetStatus(), resp.GetResponseMessage())
}

func (c *Client) GetPublicKey(ctx context.Context, cid string) ([]byte, error) {
	targetCID := strings.TrimSpace(cid)
	if targetCID == "" {
		return nil, errors.New("recipient cid is required")
	}

	var cachedKey []byte
	c.mu.RLock()
	if cached, ok := c.recipientPK[targetCID]; ok && len(cached) == 32 {
		cachedKey = cloneBytes(cached)
	}
	c.mu.RUnlock()

	callCtx, cancel := c.unaryContext(ctx)
	defer cancel()

	resp, err := c.GrpcClient.GetPublicKey(callCtx, &pb.GetPublicKeyRequest{Cid: targetCID})
	if err != nil {
		if len(cachedKey) == 32 {
			return cachedKey, nil
		}
		return nil, fmt.Errorf("GetPublicKey rpc: %w", err)
	}
	if err := statusErr("GetPublicKey", resp.GetStatus(), resp.GetResponseMessage()); err != nil {
		if len(cachedKey) == 32 {
			return cachedKey, nil
		}
		return nil, err
	}
	if !resp.GetFound() {
		if len(cachedKey) == 32 {
			return cachedKey, nil
		}
		return nil, errors.New("public key not found")
	}
	key := resp.GetPublicKey()
	if strings.HasPrefix(targetCID, "g") {
		decoded, decodeErr := decodeGroupPublicKeyPayload(key)
		if decodeErr != nil {
			return nil, decodeErr
		}
		key = decoded
	}
	if len(key) != 32 {
		return nil, errors.New("invalid public key format")
	}

	c.mu.Lock()
	c.recipientPK[targetCID] = cloneBytes(key)
	c.mu.Unlock()
	return cloneBytes(key), nil
}

func (c *Client) getRecipientBundleKeys(ctx context.Context, cid string) ([]recipientBundleKey, error) {
	callCtx, cancel := c.unaryContext(ctx)
	defer cancel()

	resp, err := c.GrpcClient.GetPublicKey(callCtx, &pb.GetPublicKeyRequest{Cid: "@bundle:" + strings.TrimSpace(cid)})
	if err != nil {
		return nil, fmt.Errorf("GetPublicKey bundle rpc: %w", err)
	}
	if err := statusErr("GetPublicKey bundle", resp.GetStatus(), resp.GetResponseMessage()); err != nil {
		return nil, err
	}
	if !resp.GetFound() || len(resp.GetPublicKey()) == 0 {
		return nil, nil
	}

	var parsed []recipientBundleKey
	if err := json.Unmarshal(resp.GetPublicKey(), &parsed); err != nil {
		return nil, fmt.Errorf("decode recipient bundle json: %w", err)
	}
	out := make([]recipientBundleKey, 0, len(parsed))
	for _, item := range parsed {
		if strings.TrimSpace(item.PublicKeyB64) == "" {
			continue
		}
		raw, err := base64.StdEncoding.DecodeString(item.PublicKeyB64)
		if err != nil || len(raw) != 32 {
			continue
		}
		out = append(out, item)
	}
	return out, nil
}

func (c *Client) buildRecipientFanoutJSON(ctx context.Context, recipientCID string, plaintext []byte) (string, error) {
	keys, err := c.getRecipientBundleKeys(ctx, recipientCID)
	if err != nil {
		return "", err
	}
	if len(keys) == 0 {
		return "", nil
	}

	envelopes := make([]recipientFanoutEnvelope, 0, len(keys))
	seenDevices := make(map[string]struct{}, len(keys))
	for _, item := range keys {
		publicRaw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(item.PublicKeyB64))
		if err != nil || len(publicRaw) != 32 {
			continue
		}
		deviceID := strings.TrimSpace(item.DeviceID)
		if deviceID != "" {
			if _, exists := seenDevices[deviceID]; exists {
				continue
			}
			seenDevices[deviceID] = struct{}{}
		}
		payload, err := encryptPayloadForRecipient(publicRaw, plaintext)
		if err != nil {
			continue
		}
		envelopes = append(envelopes, recipientFanoutEnvelope{
			DeviceID:           deviceID,
			KeyID:              item.KeyID,
			EphemeralPublicKey: base64.StdEncoding.EncodeToString(payload.GetEphemeralPublicKey()),
			IV:                 base64.StdEncoding.EncodeToString(payload.GetIv()),
			Ciphertext:         base64.StdEncoding.EncodeToString(payload.GetCiphertext()),
			MAC:                base64.StdEncoding.EncodeToString(payload.GetMac()),
		})
	}
	if len(envelopes) == 0 {
		return "", nil
	}

	raw, err := json.Marshal(envelopes)
	if err != nil {
		return "", fmt.Errorf("encode recipient fanout json: %w", err)
	}
	return string(raw), nil
}

func (c *Client) getGroupSharedKey(ctx context.Context, groupID string) ([]byte, error) {
	normalized := strings.TrimSpace(groupID)
	if normalized == "" {
		return nil, errors.New("group id is required")
	}

	var cachedKey []byte
	c.mu.RLock()
	if cached, ok := c.groupPK[normalized]; ok && len(cached) == 32 {
		cachedKey = cloneBytes(cached)
	}
	c.mu.RUnlock()

	callCtx, cancel := c.unaryContext(ctx)
	defer cancel()

	resp, err := c.GrpcClient.GetPublicKey(callCtx, &pb.GetPublicKeyRequest{Cid: normalized})
	if err != nil {
		if len(cachedKey) == 32 {
			return cachedKey, nil
		}
		return nil, fmt.Errorf("GetPublicKey group rpc: %w", err)
	}
	if err := statusErr("GetPublicKey", resp.GetStatus(), resp.GetResponseMessage()); err != nil {
		if len(cachedKey) == 32 {
			return cachedKey, nil
		}
		return nil, err
	}
	if !resp.GetFound() {
		if len(cachedKey) == 32 {
			return cachedKey, nil
		}
		return nil, errors.New("group shared key not found")
	}

	key := resp.GetPublicKey()
	decoded, decodeErr := decodeGroupPublicKeyPayload(key)
	if decodeErr != nil {
		return nil, decodeErr
	}
	key = decoded

	c.mu.Lock()
	c.groupPK[normalized] = cloneBytes(key)
	c.mu.Unlock()
	return cloneBytes(key), nil
}

func (c *Client) decryptMessageText(ctx context.Context, msg *pb.Message) (string, error) {
	if msg == nil {
		return "", errors.New("message is nil")
	}
	if strings.TrimSpace(msg.GetText()) != "" && msg.GetEncryptedData() == nil {
		return msg.GetText(), nil
	}

	payload := msg.GetEncryptedData()
	if payload == nil {
		if strings.TrimSpace(msg.GetText()) != "" {
			return msg.GetText(), nil
		}
		return "", errors.New("missing encrypted payload")
	}

	keyID := ""
	if msg.GetContentMetadata() != nil {
		keyID = strings.TrimSpace(msg.GetContentMetadata()["key_id"])
	}

	if keyID == "group" || msg.GetMessageType() == pb.MessageType_MessageType_Group {
		groupID := strings.TrimSpace(msg.GetMessageTo())
		if groupID != "" {
			groupKey, err := c.getGroupSharedKey(ctx, groupID)
			if err == nil {
				plaintext, err := decryptPayloadWithSharedKey(groupKey, payload)
				if err == nil {
					return string(plaintext), nil
				}
			}
		}
	}

	privateRaw, err := c.localPrivateKeyRaw()
	if err != nil {
		return "", err
	}
	plaintext, err := decryptPayloadWithPrivateKey(privateRaw, payload)
	if err == nil {
		return string(plaintext), nil
	}
	if strings.TrimSpace(msg.GetText()) != "" {
		return msg.GetText(), nil
	}
	return "", err
}

func (c *Client) GetLastEventRevision(ctx context.Context) (*pb.GetLastEventRevisionResponse, error) {
	callCtx, cancel := c.unaryContext(ctx)
	defer cancel()

	resp, err := c.GrpcClient.GetLastEventRevision(callCtx, &pb.GetLastEventRevisionRequest{})
	if err != nil {
		return nil, fmt.Errorf("GetLastEventRevision rpc: %w", err)
	}
	if err := statusErr("GetLastEventRevision", resp.GetStatus(), resp.GetResponseMessage()); err != nil {
		return nil, err
	}
	c.maxRevision(resp.GetCurrentRevision())
	return resp, nil
}

func (c *Client) GetLastViewRevision(ctx context.Context) (*pb.GetLastViewRevisionResponse, error) {
	callCtx, cancel := c.unaryContext(ctx)
	defer cancel()

	resp, err := c.GrpcClient.GetLastViewRevision(callCtx, &pb.GetLastViewRevisionRequest{})
	if err != nil {
		return nil, fmt.Errorf("GetLastViewRevision rpc: %w", err)
	}
	if err := statusErr("GetLastViewRevision", resp.GetStatus(), resp.GetResponseMessage()); err != nil {
		return nil, err
	}
	return resp, nil
}

func (c *Client) GetProfile(ctx context.Context) (*pb.Profile, error) {
	callCtx, cancel := c.unaryContext(ctx)
	defer cancel()

	resp, err := c.GrpcClient.GetProfile(callCtx, &pb.GetProfileRequest{})
	if err != nil {
		return nil, fmt.Errorf("GetProfile rpc: %w", err)
	}
	if err := statusErr("GetProfile", resp.GetStatus(), resp.GetResponseMessage()); err != nil {
		return nil, err
	}
	profile := resp.GetProfile()
	if profile != nil {
		c.setCID(profile.GetCid())
	}
	return profile, nil
}

func (c *Client) RefreshAuthToken(ctx context.Context, refreshToken string) (*pb.RefreshTokenResponse, error) {
	callCtx, cancel := c.unaryContext(ctx)
	defer cancel()

	refreshToken = strings.TrimSpace(refreshToken)
	if refreshToken == "" {
		refreshToken = strings.TrimSpace(c.RefreshToken)
	}
	if refreshToken == "" {
		return nil, errors.New("refresh token is required")
	}

	resp, err := c.GrpcClient.RefreshToken(callCtx, &pb.RefreshTokenRequest{
		RefreshToken: refreshToken,
	})
	if err != nil {
		return nil, fmt.Errorf("RefreshToken rpc: %w", err)
	}
	if err := statusErr("RefreshToken", resp.GetStatus(), ""); err != nil {
		return nil, err
	}

	return resp, nil
}

func (c *Client) UpdateProfile(ctx context.Context, attributes, meta map[string]string) (*pb.Profile, error) {
	callCtx, cancel := c.unaryContext(ctx)
	defer cancel()

	resp, err := c.GrpcClient.UpdateProfile(callCtx, &pb.UpdateProfileRequest{
		Attribute: cloneStringMap(attributes),
		Meta:      cloneStringMap(meta),
	})
	if err != nil {
		return nil, fmt.Errorf("UpdateProfile rpc: %w", err)
	}
	if err := statusErr("UpdateProfile", resp.GetStatus(), resp.GetResponseMessage()); err != nil {
		return nil, err
	}
	return resp.GetProfile(), nil
}

func (c *Client) SendMessage(ctx context.Context, to, text string) error {
	return c.sendPreparedMessage(ctx, to, text, pb.ContentType_NONE, nil)
}

func (c *Client) sendPreparedMessage(ctx context.Context, to, text string, contentType pb.ContentType, extraMetadata map[string]string) error {
	to = strings.TrimSpace(to)
	if to == "" {
		return errors.New("target message_to is required")
	}
	if err := c.EnsureE2EEIdentity(ctx); err != nil {
		return err
	}

	callCtx, cancel := c.unaryContext(ctx)
	defer cancel()

	messageType := messageTypeFromTarget(to)
	plaintext := []byte(text)
	contentMetadata := make(map[string]string, len(extraMetadata)+4)
	contentMetadata["e2ee"] = "1"
	for key, value := range extraMetadata {
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}
		contentMetadata[key] = value
	}

	messageText := ""
	if messageType == pb.MessageType_MessageType_Private {
		contentMetadata["e2ee_fallback_plaintext"] = "1"
		messageText = text
	}

	var encryptedPayload *pb.E2EEPayload
	var err error
	if messageType == pb.MessageType_MessageType_Group {
		groupKey, keyErr := c.getGroupSharedKey(ctx, to)
		if keyErr != nil {
			return keyErr
		}
		encryptedPayload, err = encryptPayloadWithSharedKey(groupKey, plaintext)
		if err != nil {
			return fmt.Errorf("encrypt group payload: %w", err)
		}
		contentMetadata["key_id"] = "group"
	} else {
		recipientPublicKey, keyErr := c.GetPublicKey(ctx, to)
		if keyErr != nil {
			return keyErr
		}
		encryptedPayload, err = encryptPayloadForRecipient(recipientPublicKey, plaintext)
		if err != nil {
			return fmt.Errorf("encrypt private payload: %w", err)
		}
		contentMetadata["key_id"] = "1"
		fanoutJSON, fanoutErr := c.buildRecipientFanoutJSON(ctx, to, plaintext)
		if fanoutErr == nil && fanoutJSON != "" {
			contentMetadata["e2ee_recipient_fanout"] = fanoutJSON
		}
	}

	message := &pb.Message{
		MessageFrom:     c.CurrentCID(),
		MessageTo:       to,
		MessageType:     messageType,
		CreatedTime:     time.Now().UnixMilli(),
		Text:            messageText,
		ContentType:     contentType,
		ContentMetadata: contentMetadata,
		EncryptedData:   encryptedPayload,
	}
	resp, err := c.GrpcClient.SendMessage(callCtx, &pb.SendMessageRequest{Message: message})
	if err != nil {
		return fmt.Errorf("SendMessage rpc: %w", err)
	}
	return statusErr("SendMessage", resp.GetStatus(), resp.GetResponseMessage())
}

func (c *Client) GetMessage(ctx context.Context, messageID string) (*pb.Message, error) {
	callCtx, cancel := c.unaryContext(ctx)
	defer cancel()

	resp, err := c.GrpcClient.GetMessage(callCtx, &pb.GetMessageRequest{MessageId: strings.TrimSpace(messageID)})
	if err != nil {
		return nil, fmt.Errorf("GetMessage rpc: %w", err)
	}
	if err := statusErr("GetMessage", resp.GetStatus(), resp.GetResponseMessage()); err != nil {
		return nil, err
	}
	return resp.GetMessage(), nil
}

func (c *Client) DeleteMessage(ctx context.Context, messageID string, forEveryone bool) error {
	callCtx, cancel := c.unaryContext(ctx)
	defer cancel()

	resp, err := c.GrpcClient.DeleteMessage(callCtx, &pb.DeleteMessageRequest{
		MessageId:   strings.TrimSpace(messageID),
		ForEveryone: forEveryone,
	})
	if err != nil {
		return fmt.Errorf("DeleteMessage rpc: %w", err)
	}
	return statusErr("DeleteMessage", resp.GetStatus(), resp.GetResponseMessage())
}

func (c *Client) EditMessage(ctx context.Context, messageID string, text string, metadata map[string]string) (*pb.EditMessageResponse, error) {
	callCtx, cancel := c.unaryContext(ctx)
	defer cancel()

	resp, err := c.GrpcClient.EditMessage(callCtx, &pb.EditMessageRequest{
		MessageId: strings.TrimSpace(messageID),
		Message: &pb.Message{
			Text:            text,
			ContentMetadata: cloneStringMap(metadata),
		},
	})
	if err != nil {
		return nil, fmt.Errorf("EditMessage rpc: %w", err)
	}
	if err := statusErr("EditMessage", resp.GetStatus(), resp.GetResponseMessage()); err != nil {
		return nil, err
	}
	return resp, nil
}

func (c *Client) GetOriginMessage(ctx context.Context, messageID string) (*pb.Message, error) {
	callCtx, cancel := c.unaryContext(ctx)
	defer cancel()

	resp, err := c.GrpcClient.GetOriginMessage(callCtx, &pb.GetOriginMessageRequest{MessageId: strings.TrimSpace(messageID)})
	if err != nil {
		return nil, fmt.Errorf("GetOriginMessage rpc: %w", err)
	}
	if err := statusErr("GetOriginMessage", resp.GetStatus(), resp.GetResponseMessage()); err != nil {
		return nil, err
	}
	return resp.GetOriginalMessage(), nil
}

func (c *Client) UploadMedia(ctx context.Context, filePath, category, targetID string) (*UploadedMedia, error) {
	filePath = strings.TrimSpace(filePath)
	if filePath == "" {
		return nil, errors.New("file path is required")
	}

	fileInfo, err := os.Stat(filePath)
	if err != nil {
		return nil, fmt.Errorf("stat media file: %w", err)
	}
	if fileInfo.IsDir() {
		return nil, fmt.Errorf("media path %q is a directory", filePath)
	}

	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("read media file: %w", err)
	}

	fileName := filepath.Base(filePath)
	mimeType := mime.TypeByExtension(strings.ToLower(filepath.Ext(fileName)))
	if mimeType == "" {
		mimeType = "application/octet-stream"
	}

	scopeType, scopeID := c.uploadScopeForTarget(targetID)
	encodedCategory := strings.TrimSpace(category)
	if encodedCategory == "" {
		encodedCategory = "message"
	}
	if scopeID != "" {
		encodedCategory = fmt.Sprintf("%s::%s::%s", encodedCategory, scopeType, scopeID)
	}

	callCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()

	resp, err := c.GrpcClient.UploadMedia(callCtx, &pb.UploadMediaRequest{
		Data:     data,
		FileName: fileName,
		FileType: mimeType,
		Category: encodedCategory,
	})
	if err != nil {
		return nil, fmt.Errorf("UploadMedia rpc: %w", err)
	}
	if err := statusErr("UploadMedia", resp.GetStatus(), resp.GetResponseMessage()); err != nil {
		return nil, err
	}
	return &UploadedMedia{
		URL:      strings.TrimSpace(resp.GetUrl()),
		FileName: fileName,
		MIMEType: mimeType,
		Size:     fileInfo.Size(),
	}, nil
}

func (c *Client) uploadScopeForTarget(targetID string) (scopeType, scopeID string) {
	targetID = strings.TrimSpace(targetID)
	if targetID == "" {
		return "cid", strings.TrimSpace(c.CurrentCID())
	}
	if messageTypeFromTarget(targetID) == pb.MessageType_MessageType_Group {
		return "group", targetID
	}
	return "cid", strings.TrimSpace(c.CurrentCID())
}

func (c *Client) BackupE2EEKey(ctx context.Context, encrypted []byte) error {
	callCtx, cancel := c.unaryContext(ctx)
	defer cancel()

	resp, err := c.GrpcClient.BackupE2EEKey(callCtx, &pb.BackupE2EEKeyRequest{EncryptedKeyMaterial: encrypted})
	if err != nil {
		return fmt.Errorf("BackupE2EEKey rpc: %w", err)
	}
	return statusErr("BackupE2EEKey", resp.GetStatus(), resp.GetResponseMessage())
}

func (c *Client) RestoreE2EEKey(ctx context.Context) ([]byte, error) {
	callCtx, cancel := c.unaryContext(ctx)
	defer cancel()

	resp, err := c.GrpcClient.RestoreE2EEKey(callCtx, &pb.RestoreE2EEKeyRequest{})
	if err != nil {
		return nil, fmt.Errorf("RestoreE2EEKey rpc: %w", err)
	}
	if err := statusErr("RestoreE2EEKey", resp.GetStatus(), resp.GetResponseMessage()); err != nil {
		return nil, err
	}
	return cloneBytes(resp.GetEncryptedKeyMaterial()), nil
}

func (c *Client) UpdateSettings(ctx context.Context, settings map[string]string) (map[string]string, error) {
	callCtx, cancel := c.unaryContext(ctx)
	defer cancel()

	resp, err := c.GrpcClient.UpdateSettings(callCtx, &pb.UpdateSettingsRequest{Settings: cloneStringMap(settings)})
	if err != nil {
		return nil, fmt.Errorf("UpdateSettings rpc: %w", err)
	}
	if err := statusErr("UpdateSettings", resp.GetStatus(), resp.GetResponseMessage()); err != nil {
		return nil, err
	}
	return cloneStringMap(resp.GetSettings()), nil
}

func (c *Client) GetSettings(ctx context.Context) (map[string]string, error) {
	callCtx, cancel := c.unaryContext(ctx)
	defer cancel()

	resp, err := c.GrpcClient.GetSettings(callCtx, &pb.GetSettingsRequest{})
	if err != nil {
		return nil, fmt.Errorf("GetSettings rpc: %w", err)
	}
	if err := statusErr("GetSettings", resp.GetStatus(), resp.GetResponseMessage()); err != nil {
		return nil, err
	}
	return cloneStringMap(resp.GetSettings()), nil
}

func (c *Client) SearchUsers(ctx context.Context, query string) (*pb.Contact, error) {
	callCtx, cancel := c.unaryContext(ctx)
	defer cancel()

	resp, err := c.GrpcClient.SearchUsers(callCtx, &pb.SearchUsersRequest{Query: strings.TrimSpace(query)})
	if err != nil {
		return nil, fmt.Errorf("SearchUsers rpc: %w", err)
	}
	if err := statusErr("SearchUsers", resp.GetStatus(), resp.GetResponseMessage()); err != nil {
		return nil, err
	}
	return resp.GetResult(), nil
}

func (c *Client) AddFriend(ctx context.Context, identifier string) (*pb.Contact, error) {
	callCtx, cancel := c.unaryContext(ctx)
	defer cancel()

	resp, err := c.GrpcClient.AddFriend(callCtx, &pb.AddFriendRequest{FriendIdentifier: strings.TrimSpace(identifier)})
	if err != nil {
		return nil, fmt.Errorf("AddFriend rpc: %w", err)
	}
	if err := statusErr("AddFriend", resp.GetStatus(), resp.GetResponseMessage()); err != nil {
		return nil, err
	}
	return resp.GetContact(), nil
}

func (c *Client) GetFriends(ctx context.Context) ([]*pb.Contact, error) {
	callCtx, cancel := c.unaryContext(ctx)
	defer cancel()

	resp, err := c.GrpcClient.GetFriends(callCtx, &pb.GetFriendsRequest{})
	if err != nil {
		return nil, fmt.Errorf("GetFriends rpc: %w", err)
	}
	if err := statusErr("GetFriends", resp.GetStatus(), resp.GetResponseMessage()); err != nil {
		return nil, err
	}
	return resp.GetContacts(), nil
}

func (c *Client) GetContacts(ctx context.Context, cids []string) ([]*pb.Contact, error) {
	callCtx, cancel := c.unaryContext(ctx)
	defer cancel()

	resp, err := c.GrpcClient.GetContacts(callCtx, &pb.GetContactsRequest{Cids: append([]string(nil), cids...)})
	if err != nil {
		return nil, fmt.Errorf("GetContacts rpc: %w", err)
	}
	if err := statusErr("GetContacts", resp.GetStatus(), resp.GetResponseMessage()); err != nil {
		return nil, err
	}
	return resp.GetContacts(), nil
}

func (c *Client) UpdateContact(ctx context.Context, cid string, attributes map[string]string) error {
	callCtx, cancel := c.unaryContext(ctx)
	defer cancel()

	resp, err := c.GrpcClient.UpdateContact(callCtx, &pb.UpdateContactRequest{
		Cid:        strings.TrimSpace(cid),
		Attributes: cloneStringMap(attributes),
	})
	if err != nil {
		return fmt.Errorf("UpdateContact rpc: %w", err)
	}
	return statusErr("UpdateContact", resp.GetStatus(), resp.GetResponseMessage())
}

func (c *Client) GetBlockedUsers(ctx context.Context) ([]*pb.Contact, error) {
	callCtx, cancel := c.unaryContext(ctx)
	defer cancel()

	resp, err := c.GrpcClient.GetBlockedUsers(callCtx, &pb.GetBlockedUsersRequest{})
	if err != nil {
		return nil, fmt.Errorf("GetBlockedUsers rpc: %w", err)
	}
	if err := statusErr("GetBlockedUsers", resp.GetStatus(), resp.GetResponseMessage()); err != nil {
		return nil, err
	}
	return resp.GetContacts(), nil
}

func (c *Client) CreateGroup(ctx context.Context, name string, members []string) (*pb.Group, error) {
	callCtx, cancel := c.unaryContext(ctx)
	defer cancel()

	resp, err := c.GrpcClient.CreateGroup(callCtx, &pb.CreateGroupRequest{
		Name:      strings.TrimSpace(name),
		MemberIds: append([]string(nil), members...),
	})
	if err != nil {
		return nil, fmt.Errorf("CreateGroup rpc: %w", err)
	}
	if err := statusErr("CreateGroup", resp.GetStatus(), resp.GetResponseMessage()); err != nil {
		return nil, err
	}
	return resp.GetGroup(), nil
}

func (c *Client) GetGroup(ctx context.Context, groupID string) (*pb.Group, error) {
	callCtx, cancel := c.unaryContext(ctx)
	defer cancel()

	resp, err := c.GrpcClient.GetGroup(callCtx, &pb.GetGroupRequest{GroupId: strings.TrimSpace(groupID)})
	if err != nil {
		return nil, fmt.Errorf("GetGroup rpc: %w", err)
	}
	if err := statusErr("GetGroup", resp.GetStatus(), resp.GetResponseMessage()); err != nil {
		return nil, err
	}
	return resp.GetGroup(), nil
}

func (c *Client) GetMyGroups(ctx context.Context) ([]*pb.Group, error) {
	callCtx, cancel := c.unaryContext(ctx)
	defer cancel()

	resp, err := c.GrpcClient.GetMyGroups(callCtx, &pb.GetMyGroupsRequest{})
	if err != nil {
		return nil, fmt.Errorf("GetMyGroups rpc: %w", err)
	}
	if err := statusErr("GetMyGroups", resp.GetStatus(), resp.GetResponseMessage()); err != nil {
		return nil, err
	}
	return resp.GetGroups(), nil
}

func (c *Client) UpdateGroup(ctx context.Context, groupID string, attributes map[string]string) error {
	callCtx, cancel := c.unaryContext(ctx)
	defer cancel()

	resp, err := c.GrpcClient.UpdateGroup(callCtx, &pb.UpdateGroupRequest{
		GroupId:    strings.TrimSpace(groupID),
		Attributes: cloneStringMap(attributes),
	})
	if err != nil {
		return fmt.Errorf("UpdateGroup rpc: %w", err)
	}
	return statusErr("UpdateGroup", resp.GetStatus(), resp.GetResponseMessage())
}

func (c *Client) InviteMember(ctx context.Context, groupID string, memberIDs []string) error {
	callCtx, cancel := c.unaryContext(ctx)
	defer cancel()

	resp, err := c.GrpcClient.InviteMember(callCtx, &pb.InviteMemberRequest{
		GroupId:   strings.TrimSpace(groupID),
		MemberIds: append([]string(nil), memberIDs...),
	})
	if err != nil {
		return fmt.Errorf("InviteMember rpc: %w", err)
	}
	return statusErr("InviteMember", resp.GetStatus(), resp.GetResponseMessage())
}

func (c *Client) RemoveMember(ctx context.Context, groupID, memberID string) error {
	callCtx, cancel := c.unaryContext(ctx)
	defer cancel()

	resp, err := c.GrpcClient.RemoveMember(callCtx, &pb.RemoveMemberRequest{
		GroupId:  strings.TrimSpace(groupID),
		MemberId: strings.TrimSpace(memberID),
	})
	if err != nil {
		return fmt.Errorf("RemoveMember rpc: %w", err)
	}
	return statusErr("RemoveMember", resp.GetStatus(), resp.GetResponseMessage())
}

func (c *Client) RespondInvitation(ctx context.Context, groupID string, accept bool) error {
	callCtx, cancel := c.unaryContext(ctx)
	defer cancel()

	resp, err := c.GrpcClient.RespondInvitation(callCtx, &pb.RespondInvitationRequest{
		GroupId: strings.TrimSpace(groupID),
		Accept:  accept,
	})
	if err != nil {
		return fmt.Errorf("RespondInvitation rpc: %w", err)
	}
	return statusErr("RespondInvitation", resp.GetStatus(), resp.GetResponseMessage())
}

func (c *Client) CancelInvitation(ctx context.Context, groupID, memberID string) error {
	callCtx, cancel := c.unaryContext(ctx)
	defer cancel()

	resp, err := c.GrpcClient.CancelInvitation(callCtx, &pb.CancelInvitationRequest{
		GroupId:  strings.TrimSpace(groupID),
		MemberId: strings.TrimSpace(memberID),
	})
	if err != nil {
		return fmt.Errorf("CancelInvitation rpc: %w", err)
	}
	return statusErr("CancelInvitation", resp.GetStatus(), resp.GetResponseMessage())
}

func (c *Client) GetMyGroupInvitations(ctx context.Context) ([]*pb.Group, error) {
	callCtx, cancel := c.unaryContext(ctx)
	defer cancel()

	resp, err := c.GrpcClient.GetMyGroupInvitations(callCtx, &pb.GetMyGroupInvitationsRequest{})
	if err != nil {
		return nil, fmt.Errorf("GetMyGroupInvitations rpc: %w", err)
	}
	if err := statusErr("GetMyGroupInvitations", resp.GetStatus(), resp.GetResponseMessage()); err != nil {
		return nil, err
	}
	return resp.GetInvitations(), nil
}

func (c *Client) AcceptAllPendingInvitations(ctx context.Context) error {
	invitations, err := c.GetMyGroupInvitations(ctx)
	if err != nil {
		return err
	}
	for _, invitation := range invitations {
		if invitation == nil || strings.TrimSpace(invitation.GetGroupId()) == "" {
			continue
		}
		groupID := strings.TrimSpace(invitation.GetGroupId())
		if err := c.RespondInvitation(ctx, groupID, true); err != nil {
			log.Printf("[%s] failed auto accept invitation group=%s err=%v", c.CurrentCID(), groupID, err)
			continue
		}
		log.Printf("[%s] accepted invitation group=%s", c.CurrentCID(), groupID)
	}
	return nil
}

func (c *Client) GenerateGroupURL(ctx context.Context, groupID string) (groupURL string, inviteCode string, err error) {
	callCtx, cancel := c.unaryContext(ctx)
	defer cancel()

	resp, err := c.GrpcClient.GenerateGroupUrl(callCtx, &pb.GenerateGroupUrlRequest{GroupId: strings.TrimSpace(groupID)})
	if err != nil {
		return "", "", fmt.Errorf("GenerateGroupUrl rpc: %w", err)
	}
	if err := statusErr("GenerateGroupUrl", resp.GetStatus(), resp.GetResponseMessage()); err != nil {
		return "", "", err
	}
	return strings.TrimSpace(resp.GetUrl()), strings.TrimSpace(resp.GetInviteCode()), nil
}

func (c *Client) JoinGroupByURL(ctx context.Context, inviteCodeOrURL string) error {
	callCtx, cancel := c.unaryContext(ctx)
	defer cancel()

	resp, err := c.GrpcClient.JoinGroupByUrl(callCtx, &pb.JoinGroupByUrlRequest{InviteCode: strings.TrimSpace(inviteCodeOrURL)})
	if err != nil {
		return fmt.Errorf("JoinGroupByUrl rpc: %w", err)
	}
	return statusErr("JoinGroupByUrl", resp.GetStatus(), resp.GetResponseMessage())
}

func (c *Client) FindGroupByInviteCode(ctx context.Context, inviteCode string) (*pb.Group, error) {
	callCtx, cancel := c.unaryContext(ctx)
	defer cancel()

	resp, err := c.GrpcClient.FindGroupByInviteCode(callCtx, &pb.FindGroupByInviteCodeRequest{InviteCode: strings.TrimSpace(inviteCode)})
	if err != nil {
		return nil, fmt.Errorf("FindGroupByInviteCode rpc: %w", err)
	}
	if err := statusErr("FindGroupByInviteCode", resp.GetStatus(), resp.GetResponseMessage()); err != nil {
		return nil, err
	}
	return resp.GetGroup(), nil
}

func (c *Client) GetGroupWithDisplayName(ctx context.Context, groupID string) (*pb.GroupWithDisplayName, error) {
	callCtx, cancel := c.unaryContext(ctx)
	defer cancel()

	resp, err := c.GrpcClient.GetGroupWithDisplayName(callCtx, &pb.GetGroupWithDisplayNameRequest{GroupId: strings.TrimSpace(groupID)})
	if err != nil {
		return nil, fmt.Errorf("GetGroupWithDisplayName rpc: %w", err)
	}
	if err := statusErr("GetGroupWithDisplayName", resp.GetStatus(), resp.GetResponseMessage()); err != nil {
		return nil, err
	}
	return resp.GetGroup(), nil
}

func (c *Client) LeaveGroup(ctx context.Context, groupID string) error {
	callCtx, cancel := c.unaryContext(ctx)
	defer cancel()

	resp, err := c.GrpcClient.LeaveGroup(callCtx, &pb.LeaveGroupRequest{GroupId: strings.TrimSpace(groupID)})
	if err != nil {
		return fmt.Errorf("LeaveGroup rpc: %w", err)
	}
	return statusErr("LeaveGroup", resp.GetStatus(), resp.GetResponseMessage())
}

func (c *Client) IsMemberOfGroup(ctx context.Context, groupID string) (bool, error) {
	groups, err := c.GetMyGroups(ctx)
	if err != nil {
		return false, err
	}
	for _, group := range groups {
		if group != nil && strings.TrimSpace(group.GetGroupId()) == strings.TrimSpace(groupID) {
			return true, nil
		}
	}
	return false, nil
}

func (c *Client) UpdateGroupJoinByTicket(ctx context.Context, groupID string, allow bool) error {
	return c.UpdateGroup(ctx, groupID, map[string]string{
		"join_by_ticket": fmt.Sprintf("%t", allow),
	})
}

func parseListArgs(args []string) []string {
	if len(args) == 0 {
		return nil
	}
	out := make([]string, 0, len(args))
	seen := make(map[string]struct{}, len(args))
	for _, arg := range args {
		for _, item := range strings.Split(arg, ",") {
			trimmed := strings.TrimSpace(item)
			if trimmed == "" {
				continue
			}
			if _, exists := seen[trimmed]; exists {
				continue
			}
			seen[trimmed] = struct{}{}
			out = append(out, trimmed)
		}
	}
	return out
}

func parseCreateGroupArgs(raw string) (string, []string, error) {
	parts := strings.SplitN(raw, "|", 2)
	name := strings.TrimSpace(parts[0])
	if name == "" {
		return "", nil, errors.New("group name is required")
	}
	if len(parts) == 1 {
		return name, nil, nil
	}
	memberIDs := parseListArgs([]string{parts[1]})
	return name, memberIDs, nil
}

func summarizeContacts(contacts []*pb.Contact, limit int) string {
	if len(contacts) == 0 {
		return ""
	}
	if limit <= 0 || limit > len(contacts) {
		limit = len(contacts)
	}
	names := make([]string, 0, limit)
	for _, contact := range contacts[:limit] {
		if contact == nil {
			continue
		}
		label := strings.TrimSpace(contact.GetDisplayName())
		if label == "" {
			label = strings.TrimSpace(contact.GetCid())
		}
		if label == "" {
			continue
		}
		names = append(names, label)
	}
	if len(names) == 0 {
		return ""
	}
	return "[" + strings.Join(names, ", ") + "]"
}

func summarizeGroups(groups []*pb.Group, limit int) string {
	if len(groups) == 0 {
		return ""
	}
	if limit <= 0 || limit > len(groups) {
		limit = len(groups)
	}
	names := make([]string, 0, limit)
	for _, group := range groups[:limit] {
		if group == nil {
			continue
		}
		label := strings.TrimSpace(group.GetName())
		if label == "" {
			label = strings.TrimSpace(group.GetGroupId())
		}
		if label == "" {
			continue
		}
		names = append(names, label)
	}
	if len(names) == 0 {
		return ""
	}
	return "[" + strings.Join(names, ", ") + "]"
}

func resolveGroupCommandTarget(message *pb.Message, args []string) string {
	if len(args) > 0 {
		return strings.TrimSpace(args[0])
	}
	if message == nil {
		return ""
	}
	target := strings.TrimSpace(message.GetMessageTo())
	if message.GetMessageType() == pb.MessageType_MessageType_Group {
		return target
	}
	return ""
}

func (c *Client) handleGenerateGroupURLCommand(ctx context.Context, groupID string) (groupURL string, inviteCode string, err error) {
	groupID = strings.TrimSpace(groupID)
	if groupID == "" {
		return "", "", errors.New("group target is empty")
	}
	if messageTypeFromTarget(groupID) != pb.MessageType_MessageType_Group {
		return "", "", errors.New("group target must be a group id")
	}
	if err := c.UpdateGroupJoinByTicket(ctx, groupID, true); err != nil {
		return "", "", fmt.Errorf("enable join_by_ticket: %w", err)
	}
	return c.GenerateGroupURL(ctx, groupID)
}

func (c *Client) handleJoinURLCommand(ctx context.Context, replyTarget, groupID string) error {
	groupID = strings.TrimSpace(groupID)
	if groupID == "" {
		return errors.New("group target is empty")
	}
	if messageTypeFromTarget(groupID) != pb.MessageType_MessageType_Group {
		return errors.New("group target must be a group id")
	}

	peers := snapshotPeerClients()
	if len(peers) < 2 {
		return errors.New("need at least 2 active bot clients")
	}

	var outsider *Client
	for _, peer := range peers {
		if peer == nil || peer == c || strings.TrimSpace(peer.CurrentCID()) == strings.TrimSpace(c.CurrentCID()) {
			continue
		}
		isMember, err := peer.IsMemberOfGroup(ctx, groupID)
		if err != nil {
			log.Printf("[%s] peer membership check failed peer=%s group=%s err=%v", c.CurrentCID(), peer.CurrentCID(), groupID, err)
			continue
		}
		if !isMember {
			outsider = peer
			break
		}
	}
	if outsider == nil {
		return errors.New("no outside bot found to join this group")
	}

	groupURL, inviteCode, err := c.handleGenerateGroupURLCommand(ctx, groupID)
	if err != nil {
		return fmt.Errorf("generate group url: %w", err)
	}
	if inviteCode == "" {
		inviteCode = groupURL
	}
	if strings.TrimSpace(inviteCode) == "" {
		return errors.New("invite code/url is empty")
	}

	if err := outsider.JoinGroupByURL(ctx, inviteCode); err != nil {
		return fmt.Errorf("peer join by url: %w", err)
	}

	joined, err := outsider.IsMemberOfGroup(ctx, groupID)
	if err != nil {
		return fmt.Errorf("verify joined member: %w", err)
	}
	if !joined {
		return errors.New("peer join reported success but membership not visible yet")
	}

	confirmation := fmt.Sprintf(
		"joinurl success: insider=%s outsider=%s group=%s invite=%s",
		c.CurrentCID(),
		outsider.CurrentCID(),
		groupID,
		groupURL,
	)
	return c.SendMessage(ctx, replyTarget, confirmation)
}

func (c *Client) markHandledMessage(messageID string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	if _, exists := c.handledMessages[messageID]; exists {
		return false
	}
	c.handledMessages[messageID] = struct{}{}
	c.messageOrder = append(c.messageOrder, messageID)
	if len(c.messageOrder) > 1024 {
		oldest := c.messageOrder[0]
		c.messageOrder = c.messageOrder[1:]
		delete(c.handledMessages, oldest)
	}
	return true
}

func (c *Client) logEvent(event *pb.StreamEvent, details string) {
	if event == nil {
		return
	}
	msg := fmt.Sprintf("[%s] event=%s revision=%d", c.CurrentCID(), event.GetEventType().String(), event.GetRevision())
	if strings.TrimSpace(details) != "" {
		msg += " " + strings.TrimSpace(details)
	}
	log.Print(msg)
}
