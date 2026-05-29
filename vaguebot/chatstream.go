package vaguebot

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	neturl "net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc/status"

	pb "vague-bot/proto"
)

var mumu sync.Mutex

var cekOp = make(map[int64]int)
var commandExecMu sync.Mutex
var commandExecSeen = make(map[string]struct{})
var commandExecOrder []string
var pendingPicMu sync.Mutex
var pendingChangePicTargets = map[string]string{}
var pendingSelfChangePicTargets = map[string]string{}
var pendingChangeCoverTargets = map[string]string{}

func claimCommandExecution(messageID string) bool {
	messageID = strings.TrimSpace(messageID)
	if messageID == "" {
		return true
	}

	commandExecMu.Lock()
	defer commandExecMu.Unlock()

	if _, exists := commandExecSeen[messageID]; exists {
		return false
	}
	commandExecSeen[messageID] = struct{}{}
	commandExecOrder = append(commandExecOrder, messageID)
	if len(commandExecOrder) > 2048 {
		oldest := commandExecOrder[0]
		commandExecOrder = commandExecOrder[1:]
		delete(commandExecSeen, oldest)
	}
	return true
}

func conversationTargetFromMessage(message *pb.Message) string {
	if message == nil {
		return ""
	}
	target := strings.TrimSpace(message.GetMessageTo())
	if message.GetMessageType() == pb.MessageType_MessageType_Private {
		target = strings.TrimSpace(message.GetMessageFrom())
	}
	return target
}

func setPendingChangePic(target, requesterCID string, selfOnly bool) {
	target = strings.TrimSpace(target)
	requesterCID = strings.TrimSpace(requesterCID)
	if target == "" {
		return
	}
	pendingPicMu.Lock()
	defer pendingPicMu.Unlock()
	if selfOnly {
		pendingSelfChangePicTargets[target] = requesterCID
		return
	}
	pendingChangePicTargets[target] = requesterCID
}

func consumePendingChangePic(target, senderCID string) (botPending bool, selfPending bool) {
	target = strings.TrimSpace(target)
	senderCID = strings.TrimSpace(senderCID)
	if target == "" {
		return false, false
	}
	pendingPicMu.Lock()
	defer pendingPicMu.Unlock()
	if requester, ok := pendingChangePicTargets[target]; ok && (requester == "" || requester == senderCID) {
		delete(pendingChangePicTargets, target)
		botPending = true
	}
	if requester, ok := pendingSelfChangePicTargets[target]; ok && (requester == "" || requester == senderCID) {
		delete(pendingSelfChangePicTargets, target)
		selfPending = true
	}
	return botPending, selfPending
}

func setPendingChangeCover(target, requesterCID string) {
	target = strings.TrimSpace(target)
	requesterCID = strings.TrimSpace(requesterCID)
	if target == "" {
		return
	}
	pendingPicMu.Lock()
	defer pendingPicMu.Unlock()
	pendingChangeCoverTargets[target] = requesterCID
}

func consumePendingChangeCover(target, senderCID string) (coverPending bool) {
	target = strings.TrimSpace(target)
	senderCID = strings.TrimSpace(senderCID)
	if target == "" {
		return false
	}
	pendingPicMu.Lock()
	defer pendingPicMu.Unlock()
	if requester, ok := pendingChangeCoverTargets[target]; ok && (requester == "" || requester == senderCID) {
		delete(pendingChangeCoverTargets, target)
		return true
	}
	return false
}

func mediaURLFromMessage(msg *pb.Message) string {
	if msg == nil {
		return ""
	}
	meta := msg.GetContentMetadata()
	if len(meta) == 0 {
		return ""
	}
	keys := []string{
		"image_url",
		"url",
		"media_url",
		"preview_image_url",
		"previewImageUrl",
	}
	for _, key := range keys {
		value := strings.TrimSpace(meta[key])
		if value != "" {
			return value
		}
	}
	return ""
}

func hasEncryptedMessageMediaMetadata(metadata map[string]string) bool {
	if len(metadata) == 0 {
		return false
	}
	return strings.TrimSpace(metadata["e2ee_media"]) == "1" &&
		strings.TrimSpace(metadata["e2ee_media_key"]) != "" &&
		strings.TrimSpace(metadata["e2ee_media_iv"]) != ""
}

func decodeStoredPayloadEntry(raw string) (*pb.E2EEPayload, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, errors.New("missing encrypted payload")
	}
	var entry recipientFanoutEnvelope
	if err := json.Unmarshal([]byte(raw), &entry); err != nil {
		return nil, fmt.Errorf("decode stored payload json: %w", err)
	}
	ephemeralRaw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(entry.EphemeralPublicKey))
	if err != nil {
		return nil, fmt.Errorf("decode stored payload ephemeral public key: %w", err)
	}
	ivRaw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(entry.IV))
	if err != nil {
		return nil, fmt.Errorf("decode stored payload iv: %w", err)
	}
	ciphertextRaw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(entry.Ciphertext))
	if err != nil {
		return nil, fmt.Errorf("decode stored payload ciphertext: %w", err)
	}
	macRaw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(entry.MAC))
	if err != nil {
		return nil, fmt.Errorf("decode stored payload mac: %w", err)
	}
	return &pb.E2EEPayload{
		EphemeralPublicKey: ephemeralRaw,
		Iv:                 ivRaw,
		Ciphertext:         ciphertextRaw,
		Mac:                macRaw,
	}, nil
}

func (c *Client) resolveMessageMediaKey(ctx context.Context, msg *pb.Message) ([]byte, error) {
	if msg == nil {
		return nil, errors.New("message is nil")
	}
	metadata := msg.GetContentMetadata()
	if !hasEncryptedMessageMediaMetadata(metadata) {
		return nil, errors.New("encrypted media metadata not found")
	}
	payload, err := decodeStoredPayloadEntry(metadata["e2ee_media_key"])
	if err != nil {
		return nil, err
	}

	keyID := strings.TrimSpace(metadata["e2ee_media_key_id"])
	if keyID == "group" || msg.GetMessageType() == pb.MessageType_MessageType_Group {
		groupID := strings.TrimSpace(msg.GetMessageTo())
		if groupID == "" {
			return nil, errors.New("group media missing group id")
		}
		groupKey, err := c.getGroupSharedKey(ctx, groupID)
		if err != nil {
			return nil, err
		}
		plain, err := decryptPayloadWithSharedKey(groupKey, payload)
		if err != nil {
			return nil, err
		}
		if len(plain) != 32 {
			return nil, errors.New("invalid decrypted media key length")
		}
		return plain, nil
	}

	privateKey, err := c.localPrivateKeyRaw()
	if err != nil {
		return nil, err
	}
	plain, err := decryptPayloadWithPrivateKey(privateKey, payload)
	if err != nil {
		return nil, err
	}
	if len(plain) != 32 {
		return nil, errors.New("invalid decrypted media key length")
	}
	return plain, nil
}

func decryptMessageMediaBytes(key []byte, ivB64 string, ciphertext []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, errors.New("invalid media key length")
	}
	ivRaw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(ivB64))
	if err != nil {
		return nil, fmt.Errorf("decode media iv: %w", err)
	}
	if len(ivRaw) != 12 {
		return nil, errors.New("invalid media iv length")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("init media cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("init media gcm: %w", err)
	}
	plaintext, err := gcm.Open(nil, ivRaw, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypt media payload: %w", err)
	}
	return plaintext, nil
}

func (c *Client) maybeDecryptDownloadedMediaFile(ctx context.Context, msg *pb.Message, path string) (string, error) {
	if msg == nil || strings.TrimSpace(path) == "" {
		return path, nil
	}
	metadata := msg.GetContentMetadata()
	if !hasEncryptedMessageMediaMetadata(metadata) {
		return path, nil
	}

	ciphertext, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read encrypted media file: %w", err)
	}
	key, err := c.resolveMessageMediaKey(ctx, msg)
	if err != nil {
		return "", err
	}
	plaintext, err := decryptMessageMediaBytes(key, metadata["e2ee_media_iv"], ciphertext)
	if err != nil {
		return "", err
	}
	file, err := os.CreateTemp("", "vaguebot-changepic-dec-*")
	if err != nil {
		return "", err
	}
	defer file.Close()
	if _, err := file.Write(plaintext); err != nil {
		_ = os.Remove(file.Name())
		return "", err
	}
	_ = os.Remove(path)
	return filepath.Clean(file.Name()), nil
}

func (c *Client) resolveMediaDownloadURL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", errors.New("empty media url")
	}
	if strings.HasPrefix(raw, "http://") || strings.HasPrefix(raw, "https://") {
		return raw, nil
	}

	target := strings.TrimSpace(c.cfg.Target)
	if target == "" {
		return "", errors.New("empty grpc target")
	}
	if !strings.Contains(target, "://") {
		target = "https://" + target
	}
	base, err := neturl.Parse(target)
	if err != nil {
		return "", fmt.Errorf("parse base target: %w", err)
	}
	ref, err := neturl.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("parse media url: %w", err)
	}
	return base.ResolveReference(ref).String(), nil
}

func (c *Client) downloadURLToTempFile(imageURL string) (string, error) {
	imageURL = strings.TrimSpace(imageURL)
	if imageURL == "" {
		return "", errors.New("image url is empty")
	}
	absURL, err := c.resolveMediaDownloadURL(imageURL)
	if err != nil {
		return "", err
	}
	req, err := http.NewRequest(http.MethodGet, absURL, nil)
	if err != nil {
		return "", err
	}
	if token := strings.TrimSpace(c.Token); token != "" {

		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("http status %d", resp.StatusCode)
	}

	ext := ".jpg"
	contentType := strings.ToLower(strings.TrimSpace(resp.Header.Get("Content-Type")))
	switch {
	case strings.Contains(contentType, "png"):
		ext = ".png"
	case strings.Contains(contentType, "webp"):
		ext = ".webp"
	case strings.Contains(contentType, "gif"):
		ext = ".gif"
	case strings.Contains(contentType, "bmp"):
		ext = ".bmp"
	}

	tmpFile, err := os.CreateTemp("", "vaguebot-changepic-*"+ext)
	if err != nil {
		return "", err
	}
	defer tmpFile.Close()
	if _, err := io.Copy(tmpFile, resp.Body); err != nil {
		_ = os.Remove(tmpFile.Name())
		return "", err
	}
	return filepath.Clean(tmpFile.Name()), nil
}

func (c *Client) downloadMessageObjectToTempFile(messageID string) (string, error) {
	messageID = strings.TrimSpace(messageID)
	if messageID == "" {
		return "", errors.New("message id is empty")
	}
	downloadURL := "https://obs-sg.line-apps.com/talk/m/download.nhn?oid=" + messageID
	req, err := http.NewRequest(http.MethodGet, downloadURL, nil)
	if err != nil {
		return "", err
	}
	if token := strings.TrimSpace(c.Token); token != "" {
		req.Header.Set("X-Line-Access", token)
		req.Header.Set("Authorization", "Bearer "+token)
	}
	req.Header.Set("x-lal", "en_US")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("http status %d", resp.StatusCode)
	}
	tmpFile, err := os.CreateTemp("", "vaguebot-changepic-msg-*.jpg")
	if err != nil {
		return "", err
	}
	defer tmpFile.Close()
	if _, err := io.Copy(tmpFile, resp.Body); err != nil {
		_ = os.Remove(tmpFile.Name())
		return "", err
	}
	return filepath.Clean(tmpFile.Name()), nil
}

func (c *Client) applyChangePicFromLocalPath(ctx context.Context, target, localPath string, selfOnly bool) {
	localPath = strings.TrimSpace(localPath)
	if localPath == "" {
		_ = c.SendMessage(ctx, target, "changepic failed: local image path is empty")
		return
	}
	if _, err := os.Stat(localPath); err != nil {
		_ = c.SendMessage(ctx, target, "changepic failed: local image path invalid")
		return
	}

	defer os.Remove(localPath)

	var err error
	_ = err
	_ = target
	_ = selfOnly
	// keep logic below unchanged

	var targets []*Client
	commandName := "changepic"
	entityName := "bot"
	if selfOnly {
		targets = runningSelfbotTargets(c)
		commandName = "selfchangepic"
		entityName = "selfbot"
	} else {
		targets = runningBotTargets(c)
	}
	if len(targets) == 0 {
		_ = c.SendMessage(ctx, target, commandName+" failed: no running "+entityName+" target")
		return
	}

	success := 0
	lastErr := ""
	for _, bot := range targets {
		botCID := strings.TrimSpace(bot.CurrentCID())
		if botCID == "" {
			botCID = strings.TrimSpace(bot.CID)
		}
		if botCID == "" {
			continue
		}
		uploaded, upErr := bot.UploadMedia(ctx, localPath, "profile", botCID)
		if upErr != nil {
			lastErr = upErr.Error()
			continue
		}
		if _, err := bot.UpdateProfile(ctx, map[string]string{
			"picture_profile": strings.TrimSpace(uploaded.URL),
			"video_profile":   "",
		}, nil); err != nil {
			lastErr = err.Error()
			continue
		}
		success++
	}

	if success == 0 {
		if lastErr == "" {
			lastErr = "unknown error"
		}
		_ = c.SendMessage(ctx, target, commandName+" failed: "+lastErr)
		return
	}

	msg := fmt.Sprintf("%s success: updated %d/%d %s", commandName, success, len(targets), entityName)
	if lastErr != "" && success < len(targets) {
		msg += " (last error: " + lastErr + ")"
	}
	_ = c.SendMessage(ctx, target, msg)
}

func (c *Client) applyChangePicFromURL(ctx context.Context, msg *pb.Message, target, imageURL string, selfOnly bool) {
	if strings.TrimSpace(imageURL) == "" {
		_ = c.SendMessage(ctx, target, "changepic failed: image url from message is empty")
		return
	}
	localPath, err := c.downloadURLToTempFile(imageURL)
	if err != nil {
		_ = c.SendMessage(ctx, target, "changepic failed: download image url: "+err.Error())
		return
	}
	decodedPath, decErr := c.maybeDecryptDownloadedMediaFile(ctx, msg, localPath)
	if decErr != nil {
		_ = c.SendMessage(ctx, target, "changepic failed: decrypt media: "+decErr.Error())
		return
	}
	c.applyChangePicFromLocalPath(ctx, target, decodedPath, selfOnly)
}

func (c *Client) applyChangeCoverFromLocalPath(ctx context.Context, target, localPath string) {
	localPath = strings.TrimSpace(localPath)
	if localPath == "" {
		_ = c.SendMessage(ctx, target, "changecover failed: local image path is empty")
		return
	}
	if _, err := os.Stat(localPath); err != nil {
		_ = c.SendMessage(ctx, target, "changecover failed: local image path invalid")
		return
	}
	defer os.Remove(localPath)

	targets := runningBotTargets(c)
	if len(targets) == 0 {
		_ = c.SendMessage(ctx, target, "changecover failed: no running bot target")
		return
	}

	success := 0
	lastErr := ""
	for _, bot := range targets {
		botCID := strings.TrimSpace(bot.CurrentCID())
		if botCID == "" {
			botCID = strings.TrimSpace(bot.CID)
		}
		if botCID == "" {
			continue
		}
		uploaded, err := bot.UploadMedia(ctx, localPath, "profile", botCID)
		if err != nil {
			lastErr = err.Error()
			continue
		}
		if _, err := bot.UpdateProfile(ctx, map[string]string{
			"cover_picture_profile": strings.TrimSpace(uploaded.URL),
			"cover_video_profile":   "",
		}, nil); err != nil {
			lastErr = err.Error()
			continue
		}
		success++
	}
	if success == 0 {
		if lastErr == "" {
			lastErr = "unknown error"
		}
		_ = c.SendMessage(ctx, target, "changecover failed: "+lastErr)
		return
	}
	msg := fmt.Sprintf("changecover success: updated %d/%d bot", success, len(targets))
	if lastErr != "" && success < len(targets) {
		msg += " (last error: " + lastErr + ")"
	}
	_ = c.SendMessage(ctx, target, msg)
}

func (c *Client) applyChangeCoverFromURL(ctx context.Context, msg *pb.Message, target, imageURL string) {
	if strings.TrimSpace(imageURL) == "" {
		_ = c.SendMessage(ctx, target, "changecover failed: image url from message is empty")
		return
	}
	localPath, err := c.downloadURLToTempFile(imageURL)
	if err != nil {
		_ = c.SendMessage(ctx, target, "changecover failed: download image url: "+err.Error())
		return
	}
	decodedPath, decErr := c.maybeDecryptDownloadedMediaFile(ctx, msg, localPath)
	if decErr != nil {
		_ = c.SendMessage(ctx, target, "changecover failed: decrypt media: "+decErr.Error())
		return
	}
	c.applyChangeCoverFromLocalPath(ctx, target, decodedPath)
}

func (c *Client) handlePendingProfilePictureUpdateIfNeeded(ctx context.Context, message *pb.Message) {
	if message == nil || message.GetContentType() != pb.ContentType_IMAGE {
		return
	}

	// Keep one executor for image-triggered actions.
	selfbotActive := HasActiveSelfbotClient()
	if selfbotActive {
		if !c.IsSelfbotClient() {
			return
		}
	} else if c.IsSelfbotClient() {
		return
	}

	target := conversationTargetFromMessage(message)
	if target == "" {
		return
	}
	senderCID := strings.TrimSpace(message.GetMessageFrom())
	botPending, selfPending := consumePendingChangePic(target, senderCID)
	coverPending := consumePendingChangeCover(target, senderCID)
	if !botPending && !selfPending && !coverPending {
		return
	}

	msgID := strings.TrimSpace(message.GetMessageId())
	if msgID != "" && !claimCommandExecution(msgID+"#changepic") {
		return
	}

	imageURL := mediaURLFromMessage(message)
	if botPending {
		if imageURL != "" {
			c.applyChangePicFromURL(ctx, message, target, imageURL, false)
		} else {
			localPath, err := c.downloadMessageObjectToTempFile(strings.TrimSpace(message.GetMessageId()))
			if err != nil {
				_ = c.SendMessage(ctx, target, "changepic failed: download object: "+err.Error())
				return
			}
			decodedPath, decErr := c.maybeDecryptDownloadedMediaFile(ctx, message, localPath)
			if decErr != nil {
				_ = c.SendMessage(ctx, target, "changepic failed: decrypt media: "+decErr.Error())
				return
			}
			c.applyChangePicFromLocalPath(ctx, target, decodedPath, false)
		}
	}
	if selfPending {
		if imageURL != "" {
			c.applyChangePicFromURL(ctx, message, target, imageURL, true)
		} else {
			localPath, err := c.downloadMessageObjectToTempFile(strings.TrimSpace(message.GetMessageId()))
			if err != nil {
				_ = c.SendMessage(ctx, target, "selfchangepic failed: download object: "+err.Error())
				return
			}
			decodedPath, decErr := c.maybeDecryptDownloadedMediaFile(ctx, message, localPath)
			if decErr != nil {
				_ = c.SendMessage(ctx, target, "selfchangepic failed: decrypt media: "+decErr.Error())
				return
			}
			c.applyChangePicFromLocalPath(ctx, target, decodedPath, true)
		}
	}
	if coverPending {
		if imageURL != "" {
			c.applyChangeCoverFromURL(ctx, message, target, imageURL)
		} else {
			localPath, err := c.downloadMessageObjectToTempFile(strings.TrimSpace(message.GetMessageId()))
			if err != nil {
				_ = c.SendMessage(ctx, target, "changecover failed: download object: "+err.Error())
				return
			}
			decodedPath, decErr := c.maybeDecryptDownloadedMediaFile(ctx, message, localPath)
			if decErr != nil {
				_ = c.SendMessage(ctx, target, "changecover failed: decrypt media: "+decErr.Error())
				return
			}
			c.applyChangeCoverFromLocalPath(ctx, target, decodedPath)
		}
	}
}

func cekSquad(op *pb.StreamEvent) bool {
	mumu.Lock()
	defer mumu.Unlock()
	_, ok := cekOp[op.Timestamp]
	if !ok {
		cekOp[op.Timestamp] = 1
	} else {
		return true
	}
	return false
}

func grpcStatusSummary(err error) string {
	if err == nil {
		return "grpc_code=OK"
	}
	st, ok := status.FromError(err)
	if !ok {
		return fmt.Sprintf("grpc_code=NON_GRPC raw=%q", err.Error())
	}
	return fmt.Sprintf("grpc_code=%s(%d) grpc_message=%q", st.Code().String(), int(st.Code()), st.Message())
}

func (c *Client) ChatStreamMultiEvent(ctx context.Context) error {
	startedAt := time.Now()
	startRevision := c.currentRevision()
	eventLog := func(format string, args ...any) {
		if !c.cfg.VerboseEvents {
			return
		}
		log.Printf(format, args...)
	}
	log.Printf(
		"[%s] stream open start device=%s lastRevision=%d waitForEvents=false",
		c.CurrentCID(),
		c.deviceID,
		startRevision,
	)
	stream, err := c.GrpcClient.ChatStreamMultipleEvent(ctx)
	if err != nil {
		log.Printf(
			"[%s] stream open failed err=%v %s",
			c.CurrentCID(),
			err,
			grpcStatusSummary(err),
		)
		return fmt.Errorf("ChatStreamMultipleEvent rpc: %w", err)
	}
	recvFrameCount := 0
	recvResponseCount := 0
	defer func() {
		if closeErr := stream.CloseSend(); closeErr != nil && ctx.Err() == nil {
			log.Printf(
				"[%s] stream close send failed err=%v %s",
				c.CurrentCID(),
				closeErr,
				grpcStatusSummary(closeErr),
			)
		}
		log.Printf(
			"[%s] stream closed elapsed=%s frames=%d responses=%d lastRevision=%d",
			c.CurrentCID(),
			time.Since(startedAt).Truncate(time.Millisecond),
			recvFrameCount,
			recvResponseCount,
			c.currentRevision(),
		)
	}()
	log.Printf("[%s] stream opened", c.CurrentCID())

	connectReq := &pb.StreamRequest{
		Request: &pb.StreamRequest_Connect{
			Connect: &pb.ConnectRequest{
				DeviceId:      c.deviceID,
				LastRevision:  c.currentRevision(),
				WaitForEvents: false,
			},
		},
	}
	if err := stream.Send(connectReq); err != nil {
		log.Printf(
			"[%s] stream send connect failed err=%v %s",
			c.CurrentCID(),
			err,
			grpcStatusSummary(err),
		)
		return fmt.Errorf("send connect request: %w", err)
	}
	log.Printf("[%s] stream connect request sent", c.CurrentCID())

	done := make(chan struct{})
	defer close(done)
	if c.cfg.PingInterval > 0 {
		go func() {
			ticker := time.NewTicker(c.cfg.PingInterval)
			defer ticker.Stop()
			pingCount := 0
			for {
				select {
				case <-ctx.Done():
					log.Printf("[%s] stream ping loop stop: context done", c.CurrentCID())
					return
				case <-done:
					log.Printf("[%s] stream ping loop stop: stream done", c.CurrentCID())
					return
				case <-ticker.C:
					pingReq := &pb.StreamRequest{
						Request: &pb.StreamRequest_Ping{
							Ping: &pb.PingRequest{Timestamp: time.Now().UnixMilli()},
						},
					}
					if err := stream.Send(pingReq); err != nil {
						if ctx.Err() == nil {
							log.Printf(
								"[%s] stream ping failed err=%v %s",
								c.CurrentCID(),
								err,
								grpcStatusSummary(err),
							)
						}
						return
					}
					pingCount++
					if pingCount%12 == 0 {
						log.Printf("[%s] stream ping ok count=%d", c.CurrentCID(), pingCount)
					}
				}
			}
		}()
	}

	for {
		select {
		case <-ctx.Done():
			log.Printf(
				"[%s] stream recv loop stop: context done elapsed=%s",
				c.CurrentCID(),
				time.Since(startedAt).Truncate(time.Millisecond),
			)
			return ctx.Err()
		default:
		}

		batch, err := stream.Recv()
		if err != nil {
			if errors.Is(err, io.EOF) {
				log.Printf(
					"[%s] stream recv EOF elapsed=%s frames=%d responses=%d",
					c.CurrentCID(),
					time.Since(startedAt).Truncate(time.Millisecond),
					recvFrameCount,
					recvResponseCount,
				)
				_ = c.PersistState()
				return nil
			}
			log.Printf(
				"[%s] stream recv failed err=%v %s frames=%d responses=%d elapsed=%s",
				c.CurrentCID(),
				err,
				grpcStatusSummary(err),
				recvFrameCount,
				recvResponseCount,
				time.Since(startedAt).Truncate(time.Millisecond),
			)
			return fmt.Errorf("stream recv failed: %w", err)
		}
		if batch == nil {
			continue
		}
		recvFrameCount++
		recvResponseCount += len(batch.GetResponses())
		if recvFrameCount%30 == 0 {
			log.Printf(
				"[%s] stream recv progress frames=%d responses=%d elapsed=%s",
				c.CurrentCID(),
				recvFrameCount,
				recvResponseCount,
				time.Since(startedAt).Truncate(time.Millisecond),
			)
		}

		for _, response := range batch.GetResponses() {
			if response == nil {
				continue
			}
			if connected := response.GetConnected(); connected != nil {
				c.maxRevision(connected.GetCurrentRevision())
				log.Printf("[%s] stream connected session=%s revision=%d", c.CurrentCID(), connected.GetSessionId(), connected.GetCurrentRevision())
				continue
			}
			if event := response.GetEvent(); event != nil {
				c.maxRevision(event.GetRevision())
				switch event.EventType {
				case pb.EventType_EVENT_SELF_INVITED:
					eventLog("[%s] received self invite event: %v", c.CurrentCID(), event)

				case pb.EventType_EVENT_MEMBER_INVITED:
					to, pelaku := event.Param1.GroupId, event.Param2.Cid
					invitesCon := event.GetGroupInvite().Target
					invites := []string{}
					for _, con := range invitesCon {
						invites = append(invites, con.Cid)
					}
					log.Printf("[%s] MEMBER_INVITED to=%s from=%s invites=%v myCID=%s", c.CurrentCID(), to, pelaku, invites, c.CurrentCID())
					if Contains(invites, c.CurrentCID()) {
						log.Printf("[%s] Accepting invite to group %s", c.CurrentCID(), to)
						c.RespondInvitation(ctx, to, true)
						eventLog("[%s] auto accepted member invite to group %s from %s", c.CurrentCID(), to, pelaku)
					}
					eventLog("[%s] received member invite event: %v", c.CurrentCID(), event)

				case pb.EventType_EVENT_MEMBER_REMOVED:
					if c.IsSelfbotClient() {
						continue
					}
					go func(op *pb.StreamEvent) {
						to, pelaku, korban := op.Param1.GroupId, op.Param2.Cid, op.Param3.Cid
						room := GetRoom(to)
						if c.CurrentCID() == korban {
							AddBan(pelaku, room)
							Gone(to, c, room, true)

						} else {
							if cekSquad(op) {
								if Contains(Squad, korban) {
									if !Contains(Squad, pelaku) {
										AddBan(pelaku, room)
										c.SafeClient(to, pelaku, korban, true, room)
									}
								}
							}
						}
					}(event)

				case pb.EventType_EVENT_MEMBER_JOINED:
					if c.IsSelfbotClient() {
						continue
					}
					go func(op *pb.StreamEvent) {
						to, pelaku := op.Param1.GroupId, op.Param2.Cid
						if to == "" || pelaku == "" {
							return
						}
						if IsBan(pelaku) {
							if cekSquad(op) {
								c.RemoveMember(ctx, to, pelaku)
							}
						}

					}(event)

				case pb.EventType_EVENT_INVITATION_CANCELED:
					if c.IsSelfbotClient() {
						continue
					}
					go func(op *pb.StreamEvent) {
						to, pelaku, korban := op.Param1.GroupId, op.Param2.Cid, op.Param3.Cid
						room := GetRoom(to)
						if c.CurrentCID() == korban {
							AddBan(pelaku, room)
							Gone(to, c, room, true)

						} else {
							if cekSquad(op) {
								if Contains(Squad, korban) {
									if !Contains(Squad, pelaku) {
										AddBan(pelaku, room)
										c.SafeClient(to, pelaku, korban, true, room)
									}
								}
							}
						}
					}(event)

				case pb.EventType_EVENT_SELF_UPDATE_GROUP:
					eventLog("[%s] received self update group event: %v", c.CurrentCID(), event)

				case pb.EventType_EVENT_GROUP_UPDATED:
					eventLog("[%s] received group updated event: %v", c.CurrentCID(), event)

				case pb.EventType_EVENT_SELF_JOINED:
					eventLog("[%s] received self joined event: %v", c.CurrentCID(), event)
				case pb.EventType_EVENT_SELF_REMOVED:
					eventLog("[%s] received self removed event: %v", c.CurrentCID(), event)
				case pb.EventType_EVENT_SELF_CANCEL_INVITATION:
					eventLog("[%s] received self cancel invitation event: %v", c.CurrentCID(), event)
				case pb.EventType_EVENT_MESSAGE_RECEIVED:
					if c.IsSelfbotClient() {
						continue
					}
					message := event.GetMessage()
					c.handlePendingProfilePictureUpdateIfNeeded(ctx, message)
					plainText, err := c.decryptMessageText(ctx, message)
					if err != nil {
						eventLog("[%s] failed to decrypt message %s: %v", c.CurrentCID(), message.GetMessageId(), err)
						continue
					}
					c.handleTextCommandIfNeeded(ctx, message, plainText)
				case pb.EventType_EVENT_MESSAGE_SENT:
					if !c.IsSelfbotClient() {
						continue
					}
					message := event.GetMessage()
					c.handlePendingProfilePictureUpdateIfNeeded(ctx, message)
					plainText, err := c.decryptMessageText(ctx, message)
					if err != nil {
						eventLog("[%s] failed to decrypt message %s: %v", c.CurrentCID(), message.GetMessageId(), err)
						continue
					}
					eventLog("[%s] message sent plaintext=%q", c.CurrentCID(), plainText)
					c.handleTextCommandIfNeeded(ctx, message, plainText)

				case pb.EventType_EVENT_CONTACT_ADDED:
					eventLog("[%s] received contact added event: %v", c.CurrentCID(), event)

				case pb.EventType_EVENT_MEMBER_LEFT:
					eventLog("[%s] received member left event: %v", c.CurrentCID(), event)

				case pb.EventType_EVENT_MESSAGE_READ:
					eventLog("[%s] received message read event: %v", c.CurrentCID(), event)
				default:
					eventLog("[%s] received unknown event type=%v event=%v", c.CurrentCID(), event.GetEventType(), event)
				}
			}
		}
	}
}

//go:embed commands.json
var commandsJSON string

const defaultVFlexTemplateJSON = `{"type":"vflex","version":2,"meta":{"safeArea":"true","maxHeightRatio":"0.88"},"body":{"type":"box","direction":"column","padding":12,"spacing":8,"children":[{"type":"text","text":"Halo Flex"}]}}`
const defaultVFlexCarouselTemplateJSON = `{"type":"vflex","version":2,"meta":{"safeArea":"true","maxHeightRatio":"0.88"},"altText":"VFlex Carousel Demo","body":{"type":"box","direction":"column","padding":12,"spacing":10,"backgroundColor":"#101820","borderRadius":14,"children":[{"type":"text","text":"VFlex Carousel Demo","weight":"bold","size":16,"color":"#FFFFFF"},{"type":"text","text":"Contoh carousel untuk bot Vague","size":12,"color":"#AFC4D9"},{"type":"carousel","spacing":10,"itemWidth":220,"itemHeight":198,"children":[{"type":"box","direction":"column","padding":10,"spacing":8,"backgroundColor":"#1B263B","borderRadius":12,"children":[{"type":"image","url":"https://picsum.photos/seed/vaguecar1/720/400","ratio":1.8,"fit":"cover","borderRadius":9},{"type":"text","text":"Card 1","weight":"bold","color":"#FFFFFF"},{"type":"badge","text":"Promo","backgroundColor":"#2F6DF6","textColor":"#FFFFFF","borderRadius":8}]},{"type":"box","direction":"column","padding":10,"spacing":8,"backgroundColor":"#22333B","borderRadius":12,"children":[{"type":"image","url":"https://picsum.photos/seed/vaguecar2/720/400","ratio":1.8,"fit":"cover","borderRadius":9},{"type":"text","text":"Card 2","weight":"bold","color":"#FFFFFF"},{"type":"button","label":"Buka Situs","backgroundColor":"#22A06B","textColor":"#FFFFFF","borderRadius":9,"action":{"type":"open_url","url":"https://vague-infinity.com"}}]},{"type":"box","direction":"column","padding":10,"spacing":8,"backgroundColor":"#2A1E3D","borderRadius":12,"children":[{"type":"image","url":"https://picsum.photos/seed/vaguecar3/720/400","ratio":1.8,"fit":"cover","borderRadius":9},{"type":"text","text":"Card 3","weight":"bold","color":"#FFFFFF"},{"type":"text","text":"Bisa swipe horizontal","size":12,"color":"#D2C5E8"}]}]}]}}`
const defaultVFlexStackDemoJSON = `{
  "type":"vflex",
  "version":2,
  "meta":{"safeArea":"true","maxHeightRatio":"0.88"},
  "altText":"VFlex Stack Demo",
  "body":{
    "type":"box",
    "direction":"column",
    "padding":12,
    "spacing":10,
    "backgroundColor":"#0F172A",
    "borderRadius":14,
    "children":[
      {"type":"text","text":"Stack / Overlay Demo","weight":"bold","size":16,"color":"#FFFFFF"},
      {"type":"box","direction":"stack","height":220,"borderRadius":12,"children":[
        {"type":"image","url":"https://picsum.photos/seed/vaguestack/1000/600","fit":"cover","width":4000,"height":220},
        {"type":"box","direction":"column","position":"absolute","left":12,"right":12,"bottom":12,"padding":10,"spacing":6,"backgroundColor":"#AA0F172A","borderRadius":10,"children":[
          {"type":"text","text":"Mini App Card","weight":"bold","color":"#FFFFFF"},
          {"type":"text","text":"Layer gambar + caption + CTA","size":12,"color":"#DBEAFE"}
        ]},
        {"type":"badge","text":"NEW","position":"absolute","top":10,"left":10,"backgroundColor":"#2563EB","textColor":"#FFFFFF","borderRadius":8},
        {"type":"icon","name":"play","size":44,"color":"#FFFFFF","position":"absolute","top":88,"left":148}
      ]},
      {"type":"button","label":"Lihat Detail","backgroundColor":"#2563EB","textColor":"#FFFFFF","borderRadius":10,"action":{"type":"open_url","url":"https://vague-infinity.com"}}
    ]
  }
}`
const defaultVFlexShopDemoJSON = `{
  "type":"vflex",
  "version":2,
  "meta":{"safeArea":"true","maxHeightRatio":"0.88"},
  "altText":"VFlex Shop Demo",
  "body":{
    "type":"box",
    "direction":"column",
    "padding":12,
    "spacing":10,
    "backgroundColor":"#111827",
    "borderRadius":14,
    "children":[
      {"type":"text","text":"Shop Carousel","weight":"bold","size":16,"color":"#FFFFFF"},
      {"type":"carousel","spacing":10,"itemWidth":232,"itemHeight":248,"children":[
        {"type":"box","direction":"column","padding":10,"spacing":8,"backgroundColor":"#1F2937","borderRadius":12,"children":[
          {"type":"image","url":"https://picsum.photos/seed/shop1/900/500","ratio":1.8,"fit":"cover","borderRadius":9},
          {"type":"text","text":"Sneaker Urban","weight":"bold","color":"#FFFFFF"},
          {"type":"text","text":"Rp 799.000","size":12,"color":"#93C5FD"},
          {"type":"button","label":"Beli Sekarang","backgroundColor":"#2563EB","textColor":"#FFFFFF","borderRadius":9,"action":{"type":"open_url","url":"https://vague-infinity.com"}}
        ]},
        {"type":"box","direction":"column","padding":10,"spacing":8,"backgroundColor":"#1F2937","borderRadius":12,"children":[
          {"type":"image","url":"https://picsum.photos/seed/shop2/900/500","ratio":1.8,"fit":"cover","borderRadius":9},
          {"type":"text","text":"Hoodie Basic","weight":"bold","color":"#FFFFFF"},
          {"type":"text","text":"Rp 399.000","size":12,"color":"#93C5FD"},
          {"type":"button","label":"Beli Sekarang","backgroundColor":"#059669","textColor":"#FFFFFF","borderRadius":9,"action":{"type":"open_url","url":"https://vague-infinity.com"}}
        ]},
        {"type":"box","direction":"column","padding":10,"spacing":8,"backgroundColor":"#1F2937","borderRadius":12,"children":[
          {"type":"image","url":"https://picsum.photos/seed/shop3/900/500","ratio":1.8,"fit":"cover","borderRadius":9},
          {"type":"text","text":"Smart Watch","weight":"bold","color":"#FFFFFF"},
          {"type":"text","text":"Rp 1.299.000","size":12,"color":"#93C5FD"},
          {"type":"button","label":"Beli Sekarang","backgroundColor":"#D97706","textColor":"#FFFFFF","borderRadius":9,"action":{"type":"open_url","url":"https://vague-infinity.com"}}
        ]}
      ]}
    ]
  }
}`
const defaultVFlexMenuDemoJSON = `{
  "type":"vflex",
  "version":2,
  "meta":{"safeArea":"true","maxHeightRatio":"0.88"},
  "altText":"VFlex Menu Demo",
  "body":{
    "type":"box",
    "direction":"column",
    "padding":12,
    "spacing":10,
    "backgroundColor":"#0B1324",
    "borderRadius":14,
    "children":[
      {"type":"text","text":"Quick Menu","weight":"bold","size":16,"color":"#FFFFFF"},
      {"type":"box","direction":"row","spacing":10,"children":[
        {"type":"box","direction":"column","flex":1,"padding":10,"spacing":6,"backgroundColor":"#1E293B","borderRadius":10,"action":{"type":"deep_link","url":"vague://home"},"children":[{"type":"icon","name":"home","size":22,"color":"#93C5FD"},{"type":"text","text":"Home","size":12,"color":"#E2E8F0"}]},
        {"type":"box","direction":"column","flex":1,"padding":10,"spacing":6,"backgroundColor":"#1E293B","borderRadius":10,"action":{"type":"deep_link","url":"vague://search"},"children":[{"type":"icon","name":"search","size":22,"color":"#93C5FD"},{"type":"text","text":"Search","size":12,"color":"#E2E8F0"}]},
        {"type":"box","direction":"column","flex":1,"padding":10,"spacing":6,"backgroundColor":"#1E293B","borderRadius":10,"action":{"type":"deep_link","url":"vague://chat"},"children":[{"type":"icon","name":"chat","size":22,"color":"#93C5FD"},{"type":"text","text":"Chat","size":12,"color":"#E2E8F0"}]}
      ]},
      {"type":"box","direction":"row","spacing":10,"children":[
        {"type":"box","direction":"column","flex":1,"padding":10,"spacing":6,"backgroundColor":"#1E293B","borderRadius":10,"action":{"type":"deep_link","url":"vague://wallet"},"children":[{"type":"icon","name":"cart","size":22,"color":"#86EFAC"},{"type":"text","text":"Wallet","size":12,"color":"#E2E8F0"}]},
        {"type":"box","direction":"column","flex":1,"padding":10,"spacing":6,"backgroundColor":"#1E293B","borderRadius":10,"action":{"type":"deep_link","url":"vague://calendar"},"children":[{"type":"icon","name":"calendar","size":22,"color":"#FDE68A"},{"type":"text","text":"Events","size":12,"color":"#E2E8F0"}]},
        {"type":"box","direction":"column","flex":1,"padding":10,"spacing":6,"backgroundColor":"#1E293B","borderRadius":10,"action":{"type":"deep_link","url":"vague://settings"},"children":[{"type":"icon","name":"settings","size":22,"color":"#FCA5A5"},{"type":"text","text":"Settings","size":12,"color":"#E2E8F0"}]}
      ]},
      {"type":"box","direction":"row","spacing":10,"children":[
        {"type":"box","direction":"column","flex":1,"padding":10,"spacing":6,"backgroundColor":"#1E293B","borderRadius":10,"action":{"type":"deep_link","url":"vague://profile"},"children":[{"type":"icon","name":"person","size":22,"color":"#A7F3D0"},{"type":"text","text":"Profile","size":12,"color":"#E2E8F0"}]},
        {"type":"box","direction":"column","flex":1,"padding":10,"spacing":6,"backgroundColor":"#1E293B","borderRadius":10,"action":{"type":"deep_link","url":"vague://orders"},"children":[{"type":"icon","name":"list","size":22,"color":"#BFDBFE"},{"type":"text","text":"Orders","size":12,"color":"#E2E8F0"}]},
        {"type":"box","direction":"column","flex":1,"padding":10,"spacing":6,"backgroundColor":"#1E293B","borderRadius":10,"action":{"type":"deep_link","url":"vague://explore"},"children":[{"type":"icon","name":"compass","size":22,"color":"#FBCFE8"},{"type":"text","text":"Explore","size":12,"color":"#E2E8F0"}]}
      ]},
      {"type":"box","direction":"row","spacing":10,"children":[
        {"type":"box","direction":"column","flex":1,"padding":10,"spacing":6,"backgroundColor":"#1E293B","borderRadius":10,"action":{"type":"deep_link","url":"vague://help"},"children":[{"type":"icon","name":"help","size":22,"color":"#FCD34D"},{"type":"text","text":"Help","size":12,"color":"#E2E8F0"}]},
        {"type":"box","direction":"column","flex":1,"padding":10,"spacing":6,"backgroundColor":"#1E293B","borderRadius":10,"action":{"type":"deep_link","url":"vague://rewards"},"children":[{"type":"icon","name":"gift","size":22,"color":"#C4B5FD"},{"type":"text","text":"Rewards","size":12,"color":"#E2E8F0"}]},
        {"type":"box","direction":"column","flex":1,"padding":10,"spacing":6,"backgroundColor":"#1E293B","borderRadius":10,"action":{"type":"deep_link","url":"vague://call"},"children":[{"type":"icon","name":"call","size":22,"color":"#93C5FD"},{"type":"text","text":"Calls","size":12,"color":"#E2E8F0"}]}
      ]}
    ]
  }
}`
const defaultVFlexNewsDemoJSON = `{
  "type":"vflex",
  "version":2,
  "meta":{"safeArea":"true","maxHeightRatio":"0.88"},
  "altText":"VFlex News Demo",
  "body":{
    "type":"box",
    "direction":"column",
    "padding":12,
    "spacing":9,
    "backgroundColor":"#111827",
    "borderRadius":14,
    "children":[
      {"type":"image","url":"https://picsum.photos/seed/newshero/1000/540","ratio":1.8,"fit":"cover","borderRadius":12},
      {"type":"text","text":"Breaking: Fitur Flex Kini Lebih Bebas","weight":"bold","size":16,"color":"#FFFFFF"},
      {"type":"text","text":"Atur layout seperti mini app dengan batas aman layar chat.","size":12,"color":"#CBD5E1","maxLines":3},
      {"type":"button","label":"Baca Selengkapnya","backgroundColor":"#2563EB","textColor":"#FFFFFF","borderRadius":10,"action":{"type":"open_url","url":"https://vague-infinity.com"}}
    ]
  }
}`
const defaultVFlexEventDemoJSON = `{
  "type":"vflex",
  "version":2,
  "meta":{"safeArea":"true","maxHeightRatio":"0.88"},
  "altText":"VFlex Event Demo",
  "body":{
    "type":"box",
    "direction":"column",
    "padding":12,
    "spacing":8,
    "backgroundColor":"#172554",
    "borderRadius":14,
    "children":[
      {"type":"badge","text":"LIVE EVENT","backgroundColor":"#DC2626","textColor":"#FFFFFF","borderRadius":8},
      {"type":"text","text":"Vague Creator Meetup","weight":"bold","size":16,"color":"#FFFFFF"},
      {"type":"box","direction":"row","spacing":8,"align":"center","children":[{"type":"icon","name":"calendar","size":18,"color":"#93C5FD"},{"type":"text","text":"Sabtu, 14 Juni 2026","size":12,"color":"#DBEAFE"}]},
      {"type":"box","direction":"row","spacing":8,"align":"center","children":[{"type":"icon","name":"clock","size":18,"color":"#93C5FD"},{"type":"text","text":"19:00 WIB","size":12,"color":"#DBEAFE"}]},
      {"type":"box","direction":"row","spacing":8,"align":"center","children":[{"type":"icon","name":"location","size":18,"color":"#93C5FD"},{"type":"text","text":"Jakarta Convention Hall","size":12,"color":"#DBEAFE"}]},
      {"type":"button","label":"Lihat Lokasi","backgroundColor":"#1D4ED8","textColor":"#FFFFFF","borderRadius":10,"action":{"type":"open_url","url":"https://maps.google.com"}}
    ]
  }
}`
const defaultVFlexCopyDemoJSON = `{
  "type":"vflex",
  "version":2,
  "meta":{"safeArea":"true","maxHeightRatio":"0.88"},
  "altText":"VFlex Copy Demo",
  "body":{
    "type":"box",
    "direction":"column",
    "padding":12,
    "spacing":8,
    "backgroundColor":"#14532D",
    "borderRadius":14,
    "children":[
      {"type":"text","text":"Voucher Kamu","weight":"bold","size":16,"color":"#FFFFFF"},
      {"type":"box","direction":"row","justify":"spaceBetween","align":"center","padding":10,"backgroundColor":"#166534","borderRadius":10,"children":[
        {"type":"text","text":"VAGUE-90-OFF","weight":"bold","size":15,"color":"#DCFCE7"},
        {"type":"icon","name":"copy","size":18,"color":"#DCFCE7"}
      ]},
      {"type":"button","label":"Copy Kode","backgroundColor":"#22C55E","textColor":"#052E16","borderRadius":10,"action":{"type":"copy_text","text":"VAGUE-90-OFF"}}
    ]
  }
}`
const defaultVFlexProfileDemoJSON = `{
  "type":"vflex",
  "version":2,
  "meta":{"safeArea":"true","maxHeightRatio":"0.88"},
  "altText":"VFlex Profile Demo",
  "body":{
    "type":"box",
    "direction":"column",
    "padding":12,
    "spacing":10,
    "backgroundColor":"#111827",
    "borderRadius":14,
    "children":[
      {"type":"box","direction":"row","spacing":10,"align":"center","children":[
        {"type":"image","url":"https://picsum.photos/seed/profiledemo/240/240","width":60,"height":60,"fit":"cover","borderRadius":30},
        {"type":"box","direction":"column","spacing":4,"flex":1,"children":[
          {"type":"text","text":"Vague Creator","weight":"bold","size":16,"color":"#FFFFFF"},
          {"type":"text","text":"@vaguecreator","size":12,"color":"#93C5FD"}
        ]}
      ]},
      {"type":"box","direction":"row","spacing":8,"children":[
        {"type":"box","direction":"column","flex":1,"padding":8,"backgroundColor":"#1F2937","borderRadius":10,"children":[{"type":"text","text":"12.3K","weight":"bold","color":"#FFFFFF","align":"center"},{"type":"text","text":"Followers","size":11,"color":"#9CA3AF","align":"center"}]},
        {"type":"box","direction":"column","flex":1,"padding":8,"backgroundColor":"#1F2937","borderRadius":10,"children":[{"type":"text","text":"248","weight":"bold","color":"#FFFFFF","align":"center"},{"type":"text","text":"Posts","size":11,"color":"#9CA3AF","align":"center"}]},
        {"type":"box","direction":"column","flex":1,"padding":8,"backgroundColor":"#1F2937","borderRadius":10,"children":[{"type":"text","text":"4.9","weight":"bold","color":"#FFFFFF","align":"center"},{"type":"text","text":"Rating","size":11,"color":"#9CA3AF","align":"center"}]}
      ]},
      {"type":"button","label":"Follow","backgroundColor":"#2563EB","textColor":"#FFFFFF","borderRadius":10,"action":{"type":"deep_link","url":"vague://profile/follow"}},
      {"type":"button","label":"Kirim Pesan","backgroundColor":"#0EA5E9","textColor":"#FFFFFF","borderRadius":10,"action":{"type":"deep_link","url":"vague://chat/new"}}
    ]
  }
}`
const defaultVFlexComplexDemoJSON = `{
  "type":"vflex",
  "version":2,
  "meta":{"safeArea":"true","maxHeightRatio":"0.88"},
  "altText":"VFlex Complex Demo",
  "body":{
    "type":"box",
    "direction":"column",
    "padding":12,
    "spacing":10,
    "backgroundColor":"#020617",
    "borderRadius":14,
    "children":[
      {"type":"box","direction":"stack","height":228,"borderRadius":12,"children":[
        {"type":"image","url":"https://picsum.photos/seed/vaguecomplexhero/1200/700","fit":"cover","width":4000,"height":228},
        {"type":"badge","text":"PRO EXPERIENCE","position":"absolute","top":10,"left":10,"backgroundColor":"#2563EB","textColor":"#FFFFFF","borderRadius":8},
        {"type":"box","direction":"row","position":"absolute","top":10,"right":10,"padding":6,"spacing":4,"backgroundColor":"#AA0F172A","borderRadius":8,"children":[{"type":"icon","name":"sparkles","size":14,"color":"#93C5FD"},{"type":"text","text":"Beta","size":11,"color":"#DBEAFE"}]},
        {"type":"box","direction":"column","position":"absolute","left":10,"right":10,"bottom":10,"padding":10,"spacing":6,"backgroundColor":"#AA0F172A","borderRadius":10,"children":[
          {"type":"text","text":"Creator Dashboard","weight":"bold","size":17,"color":"#FFFFFF"},
          {"type":"text","text":"Template flex kompleks: hero + stats + carousel + multi CTA","size":12,"color":"#CBD5E1","maxLines":2}
        ]}
      ]},
      {"type":"box","direction":"row","spacing":8,"children":[
        {"type":"box","direction":"column","flex":1,"padding":8,"spacing":3,"backgroundColor":"#0F172A","borderRadius":10,"children":[{"type":"text","text":"12.4K","weight":"bold","size":15,"color":"#FFFFFF","align":"center"},{"type":"text","text":"Views","size":11,"color":"#94A3B8","align":"center"}]},
        {"type":"box","direction":"column","flex":1,"padding":8,"spacing":3,"backgroundColor":"#0F172A","borderRadius":10,"children":[{"type":"text","text":"3.9K","weight":"bold","size":15,"color":"#FFFFFF","align":"center"},{"type":"text","text":"Clicks","size":11,"color":"#94A3B8","align":"center"}]},
        {"type":"box","direction":"column","flex":1,"padding":8,"spacing":3,"backgroundColor":"#0F172A","borderRadius":10,"children":[{"type":"text","text":"28%","weight":"bold","size":15,"color":"#FFFFFF","align":"center"},{"type":"text","text":"CTR","size":11,"color":"#94A3B8","align":"center"}]}
      ]},
      {"type":"box","direction":"row","justify":"spaceBetween","align":"center","children":[
        {"type":"text","text":"Featured Packs","weight":"bold","size":15,"color":"#FFFFFF"},
        {"type":"text","text":"Swipe ->","size":11,"color":"#93C5FD"}
      ]},
      {"type":"carousel","spacing":10,"itemWidth":236,"itemHeight":206,"children":[
        {"type":"box","direction":"column","padding":10,"spacing":7,"backgroundColor":"#111827","borderRadius":12,"children":[
          {"type":"image","url":"https://picsum.photos/seed/vaguecomplex1/1000/560","ratio":1.8,"fit":"cover","borderRadius":9},
          {"type":"box","direction":"row","justify":"spaceBetween","align":"center","children":[{"type":"text","text":"Starter Growth","weight":"bold","size":13,"color":"#FFFFFF"},{"type":"badge","text":"HOT","backgroundColor":"#DC2626","textColor":"#FFFFFF","borderRadius":7}]},
          {"type":"text","text":"Boost engagement cepat untuk akun baru.","size":11,"color":"#94A3B8","maxLines":2},
          {"type":"button","label":"Activate","backgroundColor":"#2563EB","textColor":"#FFFFFF","borderRadius":9,"action":{"type":"deep_link","url":"vague://pack/starter"}}
        ]},
        {"type":"box","direction":"column","padding":10,"spacing":7,"backgroundColor":"#111827","borderRadius":12,"children":[
          {"type":"image","url":"https://picsum.photos/seed/vaguecomplex2/1000/560","ratio":1.8,"fit":"cover","borderRadius":9},
          {"type":"box","direction":"row","justify":"spaceBetween","align":"center","children":[{"type":"text","text":"Creator Plus","weight":"bold","size":13,"color":"#FFFFFF"},{"type":"badge","text":"NEW","backgroundColor":"#16A34A","textColor":"#FFFFFF","borderRadius":7}]},
          {"type":"text","text":"Template visual untuk campaign mingguan.","size":11,"color":"#94A3B8","maxLines":2},
          {"type":"button","label":"Preview","backgroundColor":"#0EA5E9","textColor":"#FFFFFF","borderRadius":9,"action":{"type":"open_url","url":"https://vague-infinity.com"}}
        ]},
        {"type":"box","direction":"column","padding":10,"spacing":7,"backgroundColor":"#111827","borderRadius":12,"children":[
          {"type":"image","url":"https://picsum.photos/seed/vaguecomplex3/1000/560","ratio":1.8,"fit":"cover","borderRadius":9},
          {"type":"box","direction":"row","justify":"spaceBetween","align":"center","children":[{"type":"text","text":"Enterprise","weight":"bold","size":13,"color":"#FFFFFF"},{"type":"badge","text":"PRO","backgroundColor":"#7C3AED","textColor":"#FFFFFF","borderRadius":7}]},
          {"type":"text","text":"Automation + analytics penuh untuk tim.","size":11,"color":"#94A3B8","maxLines":2},
          {"type":"button","label":"Contact Sales","backgroundColor":"#F59E0B","textColor":"#111827","borderRadius":9,"action":{"type":"open_url","url":"https://vague-infinity.com"}}
        ]}
      ]},
      {"type":"box","direction":"row","spacing":8,"children":[
        {"type":"button","flex":1,"label":"Open App","backgroundColor":"#2563EB","textColor":"#FFFFFF","borderRadius":10,"action":{"type":"deep_link","url":"vague://home"}},
        {"type":"button","flex":1,"label":"Share","backgroundColor":"#1D4ED8","textColor":"#FFFFFF","borderRadius":10,"action":{"type":"copy_text","text":"Coba demo flexcomplex di bot Vague!"}}
      ]}
    ]
  }
}`
const defaultVFlexYouTubeDemoJSON = `{
  "type":"vflex",
  "version":2,
  "meta":{"safeArea":"true","maxHeightRatio":"0.88"},
  "altText":"VFlex YouTube Style Demo (Light)",
  "body":{
    "type":"box",
    "direction":"column",
    "padding":12,
    "spacing":10,
    "backgroundColor":"#F8FAFC",
    "borderRadius":14,
    "children":[
      {"type":"text","text":"VagueTube Preview","size":16,"weight":"bold","color":"#0F172A"},
      {"type":"video","url":"https://www.image2url.com/r2/default/videos/1779884424004-0c282c27-23b1-41d9-97a9-95c7e88f5806.mp4","ratio":1.7778,"fit":"cover","showControls":true,"autoPlay":false,"muted":false,"borderRadius":12},
      {"type":"text","text":"Cara bikin Flex Video yang clean di chat Vague","size":14,"weight":"bold","color":"#111827","maxLines":2},
      {"type":"box","direction":"row","spacing":10,"align":"center","children":[
        {"type":"image","url":"https://picsum.photos/seed/vaguechannel/120/120","width":36,"height":36,"fit":"cover","borderRadius":18},
        {"type":"box","direction":"column","spacing":2,"flex":1,"children":[
          {"type":"text","text":"Vague Creator Channel","size":12,"weight":"bold","color":"#0F172A"},
          {"type":"text","text":"128K subscribers","size":11,"color":"#64748B"}
        ]},
        {"type":"button","label":"Subscribe","padding":8,"size":12,"backgroundColor":"#FF0000","textColor":"#FFFFFF","borderRadius":18,"action":{"type":"open_url","url":"https://vague-infinity.com"}}
      ]},
      {"type":"box","direction":"row","spacing":8,"children":[
        {"type":"box","direction":"row","flex":1,"padding":8,"spacing":4,"justify":"center","align":"center","backgroundColor":"#E2E8F0","borderRadius":18,"children":[{"type":"icon","name":"heart","size":16,"color":"#0F172A"},{"type":"text","text":"Like","size":11,"color":"#0F172A"}]},
        {"type":"box","direction":"row","flex":1,"padding":8,"spacing":4,"justify":"center","align":"center","backgroundColor":"#E2E8F0","borderRadius":18,"children":[{"type":"icon","name":"chat","size":16,"color":"#0F172A"},{"type":"text","text":"Comment","size":11,"color":"#0F172A"}]},
        {"type":"box","direction":"row","flex":1,"padding":8,"spacing":4,"justify":"center","align":"center","backgroundColor":"#E2E8F0","borderRadius":18,"children":[{"type":"icon","name":"send","size":16,"color":"#0F172A"},{"type":"text","text":"Share","size":11,"color":"#0F172A"}]}
      ]}
    ]
  }
}`
const defaultVFlexSpotifyDemoJSON = `{
  "type":"vflex",
  "version":2,
  "meta":{"safeArea":"true","maxHeightRatio":"0.88"},
  "altText":"VFlex Spotify Style Demo",
  "body":{
    "type":"box",
    "direction":"column",
    "padding":12,
    "spacing":10,
    "backgroundColor":"#121212",
    "borderRadius":14,
    "children":[
      {"type":"text","text":"Now Playing","size":12,"color":"#93C5FD"},
      {"type":"box","direction":"row","spacing":10,"align":"center","children":[
        {"type":"image","url":"https://picsum.photos/seed/vaguespotifycover/280/280","width":76,"height":76,"fit":"cover","borderRadius":10},
        {"type":"box","direction":"column","flex":1,"spacing":3,"children":[
          {"type":"text","text":"Midnight Flex Session","size":15,"weight":"bold","color":"#FFFFFF","maxLines":1},
          {"type":"text","text":"Vague Audio Lab","size":12,"color":"#9CA3AF","maxLines":1},
          {"type":"badge","text":"SPOTIFY VIBE","size":10,"padding":5,"backgroundColor":"#1DB954","textColor":"#06210F","borderRadius":8}
        ]}
      ]},
      {"type":"audio","url":"https://dl.espressif.com/dl/audio/ff-16b-2c-44100hz.mp3","title":"Midnight Flex Session","artist":"Vague Audio Lab","artworkUrl":"https://picsum.photos/seed/vaguespotifycover/280/280","showProgress":true,"autoPlay":false,"loop":false,"backgroundColor":"#181818","borderRadius":12},
      {"type":"box","direction":"row","spacing":8,"children":[
        {"type":"button","label":"Open Playlist","flex":1,"padding":9,"size":12,"backgroundColor":"#1DB954","textColor":"#06210F","borderRadius":20,"action":{"type":"open_url","url":"https://open.spotify.com"}},
        {"type":"button","label":"Copy Track","flex":1,"padding":9,"size":12,"backgroundColor":"#2A2A2A","textColor":"#FFFFFF","borderRadius":20,"action":{"type":"copy_text","text":"Midnight Flex Session - Vague Audio Lab"}}
      ]}
    ]
  }
}`

// loadCommands loads command help from embedded JSON
func loadCommands() (map[string]string, error) {
	var commands map[string]string
	if err := json.Unmarshal([]byte(commandsJSON), &commands); err != nil {
		return nil, err
	}
	return commands, nil
}

func pickAutoName(raw string) (string, string) {
	selector := strings.ToLower(strings.TrimSpace(raw))
	pool := GenName
	source := "default"

	switch selector {
	case "th", "thai", "thailand":
		pool = GenThaiName
		source = "thailand"
	case "id", "indo", "indonesia":
		pool = GenIndonesian
		source = "indonesia"
	case "ar", "arb", "arab", "arabic", "rab":
		pool = GenArabic
		source = "arab"
	case "kr", "kor", "korea", "korean":
		pool = GenKoreaName
		source = "korea"
	case "jp", "jpn", "japan", "japanese":
		pool = GenJapanName
		source = "japan"
	case "jv", "java", "jawa", "javanese":
		pool = JavaName
		source = "java"
	case "us", "usa", "english", "western":
		pool = USartist
		source = "us"
	}

	if len(pool) == 0 {
		return "", source
	}
	index := int(time.Now().UnixNano() % int64(len(pool)))
	if index < 0 {
		index = -index
	}
	return strings.TrimSpace(pool[index]), source
}

func pickAutoBio(raw string) (string, string) {
	selector := strings.ToLower(strings.TrimSpace(raw))
	pool := GenStatus
	source := "default"

	switch selector {
	case "th", "thai", "thailand":
		pool = BioThai
		source = "thailand"
	case "id", "indo", "indonesia":
		pool = BioIndoneisa
		source = "indonesia"
	case "ar", "arb", "arab", "arabic", "rab":
		pool = GenArabic
		source = "arab"
	case "kr", "kor", "korea", "korean":
		pool = BioKorea
		source = "korea"
	case "jp", "jpn", "japan", "japanese":
		pool = BioJapanese
		source = "japan"
	}

	if len(pool) == 0 {
		return "", source
	}
	index := int(time.Now().UnixNano() % int64(len(pool)))
	if index < 0 {
		index = -index
	}
	return strings.TrimSpace(pool[index]), source
}

func randomFromPool(pool []string, salt int) string {
	if len(pool) == 0 {
		return ""
	}
	n := time.Now().UnixNano() + int64(salt*7919)
	if n < 0 {
		n = -n
	}
	return strings.TrimSpace(pool[int(n%int64(len(pool)))])
}

func cutNameIfLong(name string, max int) string {
	name = strings.TrimSpace(name)
	if max <= 0 {
		return name
	}
	runes := []rune(name)
	if len(runes) <= max {
		return name
	}
	return strings.TrimSpace(string(runes[:max]))
}

func buildGroupFacebookFlex(c *Client, group *pb.Group) (string, string, error) {
	if group == nil {
		return "", "", errors.New("group is nil")
	}
	groupID := strings.TrimSpace(group.GetGroupId())
	groupName := strings.TrimSpace(group.GetName())
	if groupName == "" {
		groupName = "Unnamed Group"
	}

	memberCount := 0
	inviteCount := 0
	creator := ""
	joinByTicket := false
	if extra := group.GetExtra(); extra != nil {
		memberCount = len(extra.GetMembers())
		inviteCount = len(extra.GetInvitations())
		creator = strings.TrimSpace(extra.GetCreator())
		joinByTicket = extra.GetJoinByTicket()
	}

	coverURL := c.resolvePublicAssetURL(strings.TrimSpace(group.GetCoverPicture()))
	avatarURL := c.resolvePublicAssetURL(strings.TrimSpace(group.GetPicture()))
	if coverURL == "" {
		coverURL = "https://picsum.photos/seed/vague-group-cover/1200/500"
	}
	if avatarURL == "" {
		avatarURL = "https://picsum.photos/seed/vague-group-avatar/240/240"
	}

	payload := map[string]any{
		"type":    "vflex",
		"version": 2,
		"meta": map[string]any{
			"safeArea":       "true",
			"maxHeightRatio": "0.62",
		},
		"altText": fmt.Sprintf("Group %s", groupName),
		"body": map[string]any{
			"type":            "box",
			"direction":       "column",
			"width":           240,
			"height":          240,
			"padding":         0,
			"spacing":         0,
			"backgroundColor": "#FFFFFF",
			"children": []any{
				map[string]any{
					"type":         "image",
					"url":          coverURL,
					"ratio":        3.4,
					"fit":          "cover",
					"borderRadius": 0,
				},
				map[string]any{
					"type":      "box",
					"direction": "column",
					"padding":   10,
					"spacing":   6,
					"children": []any{
						map[string]any{
							"type": "box", "direction": "row", "spacing": 10, "align": "center",
							"children": []any{
								map[string]any{"type": "image", "url": avatarURL, "width": 50, "height": 50, "fit": "cover", "borderRadius": 25},
								map[string]any{
									"type": "box", "direction": "column", "spacing": 2, "flex": 1,
									"children": []any{
										map[string]any{"type": "text", "text": groupName, "size": 14, "weight": "bold", "color": "#111827", "maxLines": 1},
										map[string]any{"type": "text", "text": fmt.Sprintf("%d members", memberCount), "size": 11, "color": "#6B7280", "maxLines": 1},
									},
								},
							},
						},
						map[string]any{
							"type": "box", "direction": "row", "spacing": 6,
							"children": []any{
								map[string]any{"type": "badge", "text": fmt.Sprintf("ID %s", cutNameIfLong(groupID, 14)), "backgroundColor": "#E5E7EB", "textColor": "#111827", "padding": 5, "borderRadius": 8},
								map[string]any{"type": "badge", "text": fmt.Sprintf("Inv %d", inviteCount), "backgroundColor": "#DBEAFE", "textColor": "#1E3A8A", "padding": 5, "borderRadius": 8},
							},
						},
						map[string]any{
							"type":            "box",
							"direction":       "column",
							"padding":         8,
							"spacing":         4,
							"backgroundColor": "#F3F4F6",
							"borderRadius":    10,
							"children": []any{
								map[string]any{"type": "text", "text": fmt.Sprintf("Creator: %s", fallbackEmpty(creator, "-")), "size": 11, "color": "#374151", "maxLines": 1},
								map[string]any{"type": "text", "text": fmt.Sprintf("Ticket %t · E2EE %t", joinByTicket, group.GetE2EeStatus()), "size": 11, "color": "#374151", "maxLines": 1},
							},
						},
					},
				},
			},
		},
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return "", "", err
	}
	return fmt.Sprintf("Group %s", groupName), string(raw), nil
}

func fallbackEmpty(value, fallback string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return fallback
	}
	return value
}

func runningBotTargets(current *Client) []*Client {
	peers := snapshotPeerClients()
	targets := make([]*Client, 0, len(peers))
	seen := make(map[string]struct{}, len(peers))

	for _, peer := range peers {
		if peer == nil || peer.IsSelfbotClient() {
			continue
		}
		cid := strings.TrimSpace(peer.CurrentCID())
		if cid == "" {
			cid = strings.TrimSpace(peer.CID)
		}
		if cid == "" {
			continue
		}
		if _, ok := seen[cid]; ok {
			continue
		}
		seen[cid] = struct{}{}
		targets = append(targets, peer)
	}

	if len(targets) == 0 && current != nil && !current.IsSelfbotClient() {
		targets = append(targets, current)
	}
	return targets
}

func runningSelfbotTargets(current *Client) []*Client {
	peers := snapshotPeerClients()
	targets := make([]*Client, 0, len(peers))
	seen := make(map[string]struct{}, len(peers))

	for _, peer := range peers {
		if peer == nil || !peer.IsSelfbotClient() {
			continue
		}
		cid := strings.TrimSpace(peer.CurrentCID())
		if cid == "" {
			cid = strings.TrimSpace(peer.CID)
		}
		if cid == "" {
			continue
		}
		if _, ok := seen[cid]; ok {
			continue
		}
		seen[cid] = struct{}{}
		targets = append(targets, peer)
	}

	if len(targets) == 0 && current != nil && current.IsSelfbotClient() {
		targets = append(targets, current)
	}
	return targets
}

func (c *Client) handleTextCommandIfNeeded(ctx context.Context, message *pb.Message, plainText string) {
	if message == nil {
		return
	}
	if strings.TrimSpace(message.GetContentMetadata()[internalBotMessageMetadataKey]) == "1" {
		return
	}

	commandLine := strings.TrimSpace(plainText)
	if commandLine == "" {
		return
	}

	parts := strings.Fields(commandLine)
	if len(parts) == 0 {
		return
	}

	from := strings.TrimSpace(message.GetMessageFrom())
	if from == "" {
		return
	}

	messageID := strings.TrimSpace(message.GetMessageId())

	target := strings.TrimSpace(message.GetMessageTo())
	if message.GetMessageType() == pb.MessageType_MessageType_Private {
		target = from
	}
	if target == "" {
		return
	}

	command := strings.ToLower(parts[0])
	if len(parts) > 1 {
		second := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(parts[1])), ":")
		if second == "failed" || second == "success" {
			return
		}
	}
	forceBotCommand := command == "kick" || command == "remove" || command == "leave" || command == "cancelinvite" || command == "cancel"
	selfbotActive := HasActiveSelfbotClient()
	if selfbotActive {
		if forceBotCommand {
			if c.IsSelfbotClient() {
				return
			}
		} else {
			if !c.IsSelfbotClient() {
				return
			}
		}
	} else if c.IsSelfbotClient() {
		return
	}
	if !claimCommandExecution(messageID) {
		return
	}
	if messageID != "" && !c.markHandledMessage(messageID) {
		return
	}

	args := parts[1:]
	rawArgs := strings.TrimSpace(strings.TrimPrefix(commandLine, parts[0]))
	if command == "ping" {
		c.GetSquad(target)
		bk := GetRoom(target).Client
		for _, cl := range bk {
			go cl.SendMessage(ctx, target, "pong")
		}
	} else if command == "sp" || command == "speed" {
		start := time.Now()
		_, err := c.GetProfile(ctx)
		latency := time.Since(start)
		if err != nil {
			_ = c.SendMessage(ctx, target, fmt.Sprintf("sp failed: %s (%d ms)", err.Error(), latency.Milliseconds()))
			return
		}
		_ = c.SendMessage(
			ctx,
			target,
			fmt.Sprintf("Speed: %d ms | %.3f s", latency.Milliseconds(), latency.Seconds()),
		)
	} else if command == "lastrev" {
		revision, err := c.GetLastEventRevision(ctx)
		if err != nil {
			_ = c.SendMessage(ctx, target, "lastrev failed: "+err.Error())
			return
		}
		_ = c.SendMessage(ctx, target, fmt.Sprintf("lastrev: last=%d current=%d session=%s", revision.GetLastEventRevision(), revision.GetCurrentRevision(), revision.GetStreamSessionId()))
	} else if command == "lastview" {
		revision, err := c.GetLastViewRevision(ctx)
		if err != nil {
			_ = c.SendMessage(ctx, target, "lastview failed: "+err.Error())
			return
		}
		_ = c.SendMessage(ctx, target, fmt.Sprintf("lastview: last=%d current=%d session=%s", revision.GetLastViewRevision(), revision.GetCurrentRevision(), revision.GetStreamSessionId()))
	} else if command == "profile" {
		profile, err := c.GetProfile(ctx)
		if err != nil {
			_ = c.SendMessage(ctx, target, "profile failed: "+err.Error())
			return
		}
		reply := fmt.Sprintf("profile: cid=%s display_name=%s user_id=%s", profile.GetCid(), profile.GetDisplayName(), profile.GetUserId())
		_ = c.SendMessage(ctx, target, reply)
	} else if command == "updatename" || command == "setname" {
		name := strings.TrimSpace(rawArgs)
		if name == "" {
			_ = c.SendMessage(ctx, target, "updatename failed: name is required")
			return
		}
		targets := runningBotTargets(c)
		if len(targets) == 0 {
			_ = c.SendMessage(ctx, target, "updatename failed: no running bot target")
			return
		}
		okCount := 0
		failCount := 0
		for _, bot := range targets {
			profile, err := bot.UpdateProfile(ctx, map[string]string{
				"display_name": name,
			}, nil)
			if err != nil {
				failCount++
				continue
			}
			if profile != nil && strings.TrimSpace(profile.GetDisplayName()) != "" {
				name = strings.TrimSpace(profile.GetDisplayName())
			}
			okCount++
		}
		_ = c.SendMessage(ctx, target, fmt.Sprintf("updatename success: %d bot updated, %d failed, name=%s", okCount, failCount, name))
	} else if command == "autoname" {
		targets := runningBotTargets(c)
		if len(targets) == 0 {
			_ = c.SendMessage(ctx, target, "autoname failed: no running bot target")
			return
		}
		modeRaw := strings.TrimSpace(rawArgs)
		mode := strings.ToLower(modeRaw)
		used := make(map[string]struct{}, len(targets)*2)
		okCount := 0
		failCount := 0
		for i, bot := range targets {
			candidate := ""
			source := "default"

			switch mode {
			case "":
				first := randomFromPool(GenName, i*2+1)
				second := randomFromPool(GenName, i*2+2)
				candidate = strings.TrimSpace(first + " " + second)
				source = "default"
			case "kr", "kor", "korea", "korean":
				candidate = randomFromPool(GenKoreaName, i+1)
				source = "korea"
			case "jp", "jpn", "japan", "japanese":
				candidate = randomFromPool(GenJapanName, i+1)
				source = "japan"
			case "ar", "arb", "arab", "arabic", "rab":
				candidate = randomFromPool(GenArabic, i+1)
				source = "arab"
			case "th", "thai", "thailand":
				candidate = randomFromPool(GenThaiName, i+1)
				source = "thailand"
			case "jv", "java", "jawa", "javanese":
				candidate = randomFromPool(JavaName, i+1)
				source = "java"
			case "id", "indo", "indonesia":
				first := randomFromPool(GenIndonesian, i*2+1)
				second := randomFromPool(GenIndonesian, i*2+2)
				candidate = strings.TrimSpace(first + " " + second)
				source = "indonesia"
			case "us", "usa", "english", "western":
				candidate = randomFromPool(USartist, i+1)
				source = "us"
			default:
				candidate = fmt.Sprintf("%s%d", strings.TrimSpace(modeRaw), i+1)
				source = "custom"
			}

			candidate = cutNameIfLong(candidate, 20)
			for candidate != "" {
				if _, exists := used[candidate]; !exists {
					break
				}
				candidate = cutNameIfLong(candidate+fmt.Sprintf("%d", i+1), 20)
			}
			if candidate == "" {
				failCount++
				continue
			}
			used[candidate] = struct{}{}

			if _, err := bot.UpdateProfile(ctx, map[string]string{
				"display_name": candidate,
			}, nil); err != nil {
				failCount++
				continue
			}
			_ = bot.SendMessage(ctx, target, fmt.Sprintf("Update name to : %s (%s)", candidate, source))
			okCount++
		}
		_ = c.SendMessage(ctx, target, fmt.Sprintf("autoname done: %d bot updated, %d failed", okCount, failCount))
	} else if command == "updatebio" || command == "setbio" {
		bio := strings.TrimSpace(rawArgs)
		if bio == "" {
			_ = c.SendMessage(ctx, target, "updatebio failed: bio is required")
			return
		}
		targets := runningBotTargets(c)
		if len(targets) == 0 {
			_ = c.SendMessage(ctx, target, "updatebio failed: no running bot target")
			return
		}
		okCount := 0
		failCount := 0
		for _, bot := range targets {
			profile, err := bot.UpdateProfile(ctx, map[string]string{
				"status_message": bio,
			}, nil)
			if err != nil {
				failCount++
				continue
			}
			if profile != nil && strings.TrimSpace(profile.GetStatusMessage()) != "" {
				bio = strings.TrimSpace(profile.GetStatusMessage())
			}
			okCount++
		}
		_ = c.SendMessage(ctx, target, fmt.Sprintf("updatebio success: %d bot updated, %d failed, bio=%s", okCount, failCount, bio))
	} else if command == "autobio" {
		bio, source := pickAutoBio(rawArgs)
		if bio == "" {
			_ = c.SendMessage(ctx, target, "autobio failed: bio source is empty")
			return
		}
		targets := runningBotTargets(c)
		if len(targets) == 0 {
			_ = c.SendMessage(ctx, target, "autobio failed: no running bot target")
			return
		}
		okCount := 0
		failCount := 0
		for _, bot := range targets {
			if _, err := bot.UpdateProfile(ctx, map[string]string{
				"status_message": bio,
			}, nil); err != nil {
				failCount++
				continue
			}
			okCount++
		}
		_ = c.SendMessage(ctx, target, fmt.Sprintf("autobio success (%s): %d bot updated, %d failed, bio=%s", source, okCount, failCount, bio))
	} else if command == "friends" {
		targets := runningBotTargets(c)
		if len(targets) == 0 {
			_ = c.SendMessage(ctx, target, "friends failed: no running bot target")
			return
		}

		const chunkSize = 100
		for _, bot := range targets {
			contacts, err := bot.GetFriends(ctx)
			if err != nil {
				_ = bot.SendMessage(ctx, target, "friends failed: "+err.Error())
				continue
			}

			botCID := strings.TrimSpace(bot.CurrentCID())
			if botCID == "" {
				botCID = strings.TrimSpace(bot.CID)
			}
			friendIDs := make([]string, 0, len(contacts))
			for _, contact := range contacts {
				if contact == nil {
					continue
				}
				cid := strings.TrimSpace(contact.GetCid())
				if cid == "" {
					continue
				}
				friendIDs = append(friendIDs, cid)
			}
			if len(friendIDs) == 0 {
				continue
			}

			for i := 0; i < len(friendIDs); i += chunkSize {
				end := i + chunkSize
				if end > len(friendIDs) {
					end = len(friendIDs)
				}
				chunk := friendIDs[i:end]
				lines := make([]string, 0, len(chunk))
				for j, cid := range chunk {
					lines = append(lines, fmt.Sprintf("%d. @%s", i+j+1, cid))
				}
				text := strings.Join(lines, "\n")
				_ = bot.SendMention(ctx, target, text, chunk)
			}
		}
	} else if command == "groups" {
		groups, err := c.GetMyGroups(ctx)
		if err != nil {
			_ = c.SendMessage(ctx, target, "groups failed: "+err.Error())
			return
		}
		_ = c.SendMessage(ctx, target, fmt.Sprintf("groups: %d %s", len(groups), summarizeGroups(groups, 3)))
	} else if command == "settings" {
		if len(args) >= 3 && strings.EqualFold(args[0], "set") {
			key := strings.TrimSpace(args[1])
			value := strings.TrimSpace(strings.Join(args[2:], " "))
			if key == "" {
				_ = c.SendMessage(ctx, target, "settings set failed: key is required")
				return
			}
			updated, err := c.UpdateSettings(ctx, map[string]string{key: value})
			if err != nil {
				_ = c.SendMessage(ctx, target, "settings set failed: "+err.Error())
				return
			}
			_ = c.SendMessage(ctx, target, fmt.Sprintf("settings set: %s=%s total=%d", key, updated[key], len(updated)))
			return
		}
		settings, err := c.GetSettings(ctx)
		if err != nil {
			_ = c.SendMessage(ctx, target, "settings failed: "+err.Error())
			return
		}
		_ = c.SendMessage(ctx, target, fmt.Sprintf("settings: %d entries", len(settings)))
	} else if command == "search" {
		query := strings.TrimSpace(strings.Join(args, " "))
		if query == "" {
			_ = c.SendMessage(ctx, target, "search failed: query is required")
			return
		}
		contact, err := c.SearchUsers(ctx, query)
		if err != nil {
			_ = c.SendMessage(ctx, target, "search failed: "+err.Error())
			return
		}
		if contact == nil {
			_ = c.SendMessage(ctx, target, "search: no result")
			return
		}
		cid := strings.TrimSpace(contact.GetCid())
		if cid == "" {
			_ = c.SendMessage(ctx, target, "search: no result")
			return
		}
		if err := c.SendContact(ctx, target, cid); err != nil {
			_ = c.SendMessage(ctx, target, fmt.Sprintf("search: cid=%s display_name=%s", contact.GetCid(), contact.GetDisplayName()))
		}
	} else if command == "addfriend" {
		identifier := strings.TrimSpace(strings.Join(args, " "))
		if identifier == "" {
			_ = c.SendMessage(ctx, target, "addfriend failed: identifier is required")
			return
		}
		contact, err := c.AddFriend(ctx, identifier)
		if err != nil {
			_ = c.SendMessage(ctx, target, "addfriend failed: "+err.Error())
			return
		}
		_ = c.SendMessage(ctx, target, fmt.Sprintf("addfriend: cid=%s display_name=%s", contact.GetCid(), contact.GetDisplayName()))
	} else if command == "addall" {
		targets := runningBotTargets(c)
		if len(targets) < 2 {
			_ = c.SendMessage(ctx, target, "addall failed: need at least 2 running bot")
			return
		}

		success := 0
		failed := 0
		skipped := 0
		lastErr := ""
		for i := 0; i < len(targets); i++ {
			src := targets[i]
			srcCID := strings.TrimSpace(src.CurrentCID())
			if srcCID == "" {
				srcCID = strings.TrimSpace(src.CID)
			}
			if srcCID == "" {
				continue
			}
			for j := 0; j < len(targets); j++ {
				if i == j {
					continue
				}
				dst := targets[j]
				dstCID := strings.TrimSpace(dst.CurrentCID())
				if dstCID == "" {
					dstCID = strings.TrimSpace(dst.CID)
				}
				if dstCID == "" || dstCID == srcCID {
					skipped++
					continue
				}

				if _, err := src.AddFriend(ctx, dstCID); err != nil {
					failed++
					lastErr = err.Error()
					continue
				}
				success++
			}
		}

		msg := fmt.Sprintf(
			"addall done: bots=%d success=%d failed=%d skipped=%d",
			len(targets),
			success,
			failed,
			skipped,
		)
		if lastErr != "" {
			msg += " last_error=" + lastErr
		}
		_ = c.SendMessage(ctx, target, msg)
	} else if command == "contacts" {
		cids := parseListArgs(args)
		if len(cids) == 0 {
			_ = c.SendMessage(ctx, target, "contacts failed: provide at least one cid")
			return
		}
		contacts, err := c.GetContacts(ctx, cids)
		if err != nil {
			_ = c.SendMessage(ctx, target, "contacts failed: "+err.Error())
			return
		}
		_ = c.SendMessage(ctx, target, fmt.Sprintf("contacts: %d %s", len(contacts), summarizeContacts(contacts, 5)))
	} else if command == "blocked" {
		contacts, err := c.GetBlockedUsers(ctx)
		if err != nil {
			_ = c.SendMessage(ctx, target, "blocked failed: "+err.Error())
			return
		}
		_ = c.SendMessage(ctx, target, fmt.Sprintf("blocked: %d %s", len(contacts), summarizeContacts(contacts, 5)))
	} else if command == "creategroup" {
		name, members, err := parseCreateGroupArgs(strings.TrimSpace(strings.Join(args, " ")))
		if err != nil {
			_ = c.SendMessage(ctx, target, "creategroup failed: "+err.Error())
			return
		}
		group, err := c.CreateGroup(ctx, name, members)
		if err != nil {
			_ = c.SendMessage(ctx, target, "creategroup failed: "+err.Error())
			return
		}
		_ = c.SendMessage(ctx, target, fmt.Sprintf("creategroup: id=%s name=%s", group.GetGroupId(), group.GetName()))
	} else if command == "group" {
		groupID := resolveGroupCommandTarget(message, args)
		group, err := c.GetGroup(ctx, groupID)
		if err != nil {
			_ = c.SendMessage(ctx, target, "group failed: "+err.Error())
			return
		}
		memberCount := 0
		if group.GetExtra() != nil {
			memberCount = len(group.GetExtra().GetMembers())
		}
		altText, flexJSON, flexErr := buildGroupFacebookFlex(c, group)
		if flexErr == nil {
			if err := c.SendFlexMessage(ctx, target, flexJSON, altText); err == nil {
				return
			}
		}
		_ = c.SendMessage(ctx, target, fmt.Sprintf("group: id=%s name=%s members=%d", group.GetGroupId(), group.GetName(), memberCount))
	} else if command == "groupname" {
		groupID := resolveGroupCommandTarget(message, args)
		group, err := c.GetGroupWithDisplayName(ctx, groupID)
		if err != nil {
			_ = c.SendMessage(ctx, target, "groupname failed: "+err.Error())
			return
		}
		memberCount := 0
		if group.GetExtra() != nil {
			memberCount = len(group.GetExtra().GetMembers())
		}
		_ = c.SendMessage(ctx, target, fmt.Sprintf("groupname: id=%s name=%s members=%d", group.GetGroupId(), group.GetName(), memberCount))
	} else if command == "tagall" {
		if message.GetMessageType() != pb.MessageType_MessageType_Group {
			_ = c.SendMessage(ctx, target, "tagall failed: group only")
			return
		}
		groupID := strings.TrimSpace(message.GetMessageTo())
		group, err := c.GetGroup(ctx, groupID)
		if err != nil || group == nil || group.GetExtra() == nil {
			_ = c.SendMessage(ctx, target, "tagall failed: cannot load group members")
			return
		}
		memberIDs := make([]string, 0, len(group.GetExtra().GetMembers()))
		for mid := range group.GetExtra().GetMembers() {
			mid = strings.TrimSpace(mid)
			if mid != "" {
				memberIDs = append(memberIDs, mid)
			}
		}
		if len(memberIDs) == 0 {
			_ = c.SendMessage(ctx, target, "tagall: no members")
			return
		}

		const chunkSize = 100
		sent := 0
		for i := 0; i < len(memberIDs); i += chunkSize {
			end := i + chunkSize
			if end > len(memberIDs) {
				end = len(memberIDs)
			}
			chunk := memberIDs[i:end]
			lines := make([]string, 0, len(chunk))
			for j, mid := range chunk {
				lines = append(lines, fmt.Sprintf("%d. @%s", i+j+1, strings.TrimSpace(mid)))
			}
			text := strings.Join(lines, "\n")
			if err := c.SendMention(ctx, target, text, chunk); err == nil {
				sent++
			}
		}
		if sent == 0 {
			_ = c.SendMessage(ctx, target, "tagall failed: cannot send mention")
			return
		}
	} else if command == "invite" {
		if len(args) < 2 {
			_ = c.SendMessage(ctx, target, "invite failed: usage invite <group_id> <cid...>")
			return
		}
		groupID := strings.TrimSpace(args[0])
		memberIDs := parseListArgs(args[1:])
		if err := c.InviteMember(ctx, groupID, memberIDs); err != nil {
			_ = c.SendMessage(ctx, target, "invite failed: "+err.Error())
			return
		}
		_ = c.SendMessage(ctx, target, fmt.Sprintf("invite: group=%s count=%d", groupID, len(memberIDs)))
	} else if command == "remove" {
		if len(args) < 2 {
			_ = c.SendMessage(ctx, target, "remove failed: usage remove <group_id> <cid>")
			return
		}
		groupID := strings.TrimSpace(args[0])
		memberID := strings.TrimSpace(args[1])
		if err := c.RemoveMember(ctx, groupID, memberID); err != nil {
			_ = c.SendMessage(ctx, target, "remove failed: "+err.Error())
			return
		}
		_ = c.SendMessage(ctx, target, fmt.Sprintf("remove: group=%s member=%s", groupID, memberID))
	} else if command == "cancelinvite" {
		if len(args) < 2 {
			_ = c.SendMessage(ctx, target, "cancelinvite failed: usage cancelinvite <group_id> <cid>")
			return
		}
		groupID := strings.TrimSpace(args[0])
		memberID := strings.TrimSpace(args[1])
		if err := c.CancelInvitation(ctx, groupID, memberID); err != nil {
			_ = c.SendMessage(ctx, target, "cancelinvite failed: "+err.Error())
			return
		}
		_ = c.SendMessage(ctx, target, fmt.Sprintf("cancelinvite: group=%s member=%s", groupID, memberID))
	} else if command == "invitations" {
		invitations, err := c.GetMyGroupInvitations(ctx)
		if err != nil {
			_ = c.SendMessage(ctx, target, "invitations failed: "+err.Error())
			return
		}
		_ = c.SendMessage(ctx, target, fmt.Sprintf("invitations: %d %s", len(invitations), summarizeGroups(invitations, 5)))
	} else if command == "findinvite" {
		code := strings.TrimSpace(strings.Join(args, " "))
		if code == "" {
			_ = c.SendMessage(ctx, target, "findinvite failed: code is required")
			return
		}
		group, err := c.FindGroupByInviteCode(ctx, code)
		if err != nil {
			_ = c.SendMessage(ctx, target, "findinvite failed: "+err.Error())
			return
		}
		_ = c.SendMessage(ctx, target, fmt.Sprintf("findinvite: id=%s name=%s", group.GetGroupId(), group.GetName()))
	} else if command == "groupurl" {
		groupID := resolveGroupCommandTarget(message, args)
		groupURL, inviteCode, err := c.handleGenerateGroupURLCommand(ctx, groupID)
		if err != nil {
			_ = c.SendMessage(ctx, target, "groupurl failed: "+err.Error())
			return
		}
		reply := "groupurl success: " + groupURL
		if inviteCode != "" {
			reply += " code=" + inviteCode
		}
		_ = c.SendMessage(ctx, target, reply)
	} else if command == "joinurl" {
		groupID := resolveGroupCommandTarget(message, args)
		if err := c.handleJoinURLCommand(ctx, target, groupID); err != nil {
			_ = c.SendMessage(ctx, target, "joinurl failed: "+err.Error())
		}
	} else if command == "leavegroup" {
		groupID := resolveGroupCommandTarget(message, args)
		if err := c.LeaveGroup(ctx, groupID); err != nil {
			_ = c.SendMessage(ctx, target, "leavegroup failed: "+err.Error())
			return
		}
		if message.GetMessageType() != pb.MessageType_MessageType_Group {
			_ = c.SendMessage(ctx, target, "leavegroup success: "+groupID)
		}
	} else if command == "getmsg" {
		messageID := strings.TrimSpace(strings.Join(args, " "))
		if messageID == "" {
			_ = c.SendMessage(ctx, target, "getmsg failed: message id is required")
			return
		}
		msg, err := c.GetMessage(ctx, messageID)
		if err != nil {
			_ = c.SendMessage(ctx, target, "getmsg failed: "+err.Error())
			return
		}
		_ = c.SendMessage(ctx, target, fmt.Sprintf("getmsg: id=%s from=%s to=%s text=%q", msg.GetMessageId(), msg.GetMessageFrom(), msg.GetMessageTo(), msg.GetText()))
	} else if command == "origin" {
		messageID := strings.TrimSpace(strings.Join(args, " "))
		if messageID == "" {
			_ = c.SendMessage(ctx, target, "origin failed: message id is required")
			return
		}
		msg, err := c.GetOriginMessage(ctx, messageID)
		if err != nil {
			_ = c.SendMessage(ctx, target, "origin failed: "+err.Error())
			return
		}
		_ = c.SendMessage(ctx, target, fmt.Sprintf("origin: id=%s from=%s text=%q", msg.GetMessageId(), msg.GetMessageFrom(), msg.GetText()))
	} else if command == "edit" {
		if len(args) < 2 {
			_ = c.SendMessage(ctx, target, "edit failed: usage edit <message_id> <text>")
			return
		}
		messageID := strings.TrimSpace(args[0])
		text := strings.TrimSpace(strings.Join(args[1:], " "))
		if _, err := c.EditMessage(ctx, messageID, text, nil); err != nil {
			_ = c.SendMessage(ctx, target, "edit failed: "+err.Error())
			return
		}
		_ = c.SendMessage(ctx, target, "edit success: "+messageID)
	} else if command == "delete" {
		if len(args) < 1 {
			_ = c.SendMessage(ctx, target, "delete failed: usage delete <message_id> [all]")
			return
		}
		messageID := strings.TrimSpace(args[0])
		forEveryone := len(args) > 1 && strings.EqualFold(strings.TrimSpace(args[1]), "all")
		if err := c.DeleteMessage(ctx, messageID, forEveryone); err != nil {
			_ = c.SendMessage(ctx, target, "delete failed: "+err.Error())
			return
		}
		_ = c.SendMessage(ctx, target, fmt.Sprintf("delete success: %s all=%t", messageID, forEveryone))
	} else if command == "upload" {
		if len(args) < 1 {
			_ = c.SendMessage(ctx, target, "upload failed: usage upload <path> [category] [target]")
			return
		}
		filePath := strings.TrimSpace(args[0])
		category := "message"
		uploadTarget := target
		if len(args) > 1 && strings.TrimSpace(args[1]) != "" {
			category = strings.TrimSpace(args[1])
		}
		if len(args) > 2 && strings.TrimSpace(args[2]) != "" {
			uploadTarget = strings.TrimSpace(args[2])
		}
		uploaded, err := c.UploadMedia(ctx, filePath, category, uploadTarget)
		if err != nil {
			_ = c.SendMessage(ctx, target, "upload failed: "+err.Error())
			return
		}
		_ = c.SendMessage(ctx, target, fmt.Sprintf("upload success: url=%s size=%d mime=%s", uploaded.URL, uploaded.Size, uploaded.MIMEType))
	} else if command == "sendimage" {
		if len(args) < 1 {
			_ = c.SendMessage(ctx, target, "sendimage failed: usage sendimage <path_or_url> [target]")
			return
		}
		mediaPath := strings.TrimSpace(args[0])
		sendTarget := target
		if len(args) > 1 && strings.TrimSpace(args[1]) != "" {
			sendTarget = strings.TrimSpace(args[1])
		}
		if err := c.SendImage(ctx, sendTarget, mediaPath); err != nil {
			_ = c.SendMessage(ctx, target, "sendimage failed: "+err.Error())
			return
		}
		_ = c.SendMessage(ctx, target, "sendimage success")
	} else if command == "sendaudio" {
		if len(args) < 1 {
			_ = c.SendMessage(ctx, target, "sendaudio failed: usage sendaudio <path_or_url> [target]")
			return
		}
		mediaPath := strings.TrimSpace(args[0])
		sendTarget := target
		if len(args) > 1 && strings.TrimSpace(args[1]) != "" {
			sendTarget = strings.TrimSpace(args[1])
		}
		if err := c.SendAudio(ctx, sendTarget, mediaPath); err != nil {
			_ = c.SendMessage(ctx, target, "sendaudio failed: "+err.Error())
			return
		}
		_ = c.SendMessage(ctx, target, "sendaudio success")
	} else if command == "sendvideo" {
		if len(args) < 1 {
			_ = c.SendMessage(ctx, target, "sendvideo failed: usage sendvideo <path_or_url> [target]")
			return
		}
		mediaPath := strings.TrimSpace(args[0])
		sendTarget := target
		if len(args) > 1 && strings.TrimSpace(args[1]) != "" {
			sendTarget = strings.TrimSpace(args[1])
		}
		if err := c.SendVideo(ctx, sendTarget, mediaPath); err != nil {
			_ = c.SendMessage(ctx, target, "sendvideo failed: "+err.Error())
			return
		}
		_ = c.SendMessage(ctx, target, "sendvideo success")
	} else if command == "changepic" {
		filePath := strings.TrimSpace(rawArgs)
		if filePath == "" {
			setPendingChangePic(target, strings.TrimSpace(message.GetMessageFrom()), false)
			_ = c.SendMessage(ctx, target, "Send your image.")
			return
		}
		targets := runningBotTargets(c)
		if len(targets) == 0 {
			_ = c.SendMessage(ctx, target, "changepic failed: no running bot target")
			return
		}

		success := 0
		lastErr := ""
		for _, bot := range targets {
			botCID := strings.TrimSpace(bot.CurrentCID())
			if botCID == "" {
				botCID = strings.TrimSpace(bot.CID)
			}
			if botCID == "" {
				continue
			}

			uploaded, err := bot.UploadMedia(ctx, filePath, "profile", botCID)
			if err != nil {
				lastErr = err.Error()
				continue
			}
			if _, err := bot.UpdateProfile(ctx, map[string]string{
				"picture_profile": strings.TrimSpace(uploaded.URL),
				"video_profile":   "",
			}, nil); err != nil {
				lastErr = err.Error()
				continue
			}
			success++
		}

		if success == 0 {
			if lastErr == "" {
				lastErr = "unknown error"
			}
			_ = c.SendMessage(ctx, target, "changepic failed: "+lastErr)
			return
		}

		msg := fmt.Sprintf("changepic success: updated %d/%d bot", success, len(targets))
		if lastErr != "" && success < len(targets) {
			msg += " (last error: " + lastErr + ")"
		}
		_ = c.SendMessage(ctx, target, msg)
	} else if command == "changecover" {
		filePath := strings.TrimSpace(rawArgs)
		if filePath == "" {
			setPendingChangeCover(target, strings.TrimSpace(message.GetMessageFrom()))
			_ = c.SendMessage(ctx, target, "Send your image.")
			return
		}
		c.applyChangeCoverFromLocalPath(ctx, target, filePath)
	} else if command == "selfchangepic" {
		filePath := strings.TrimSpace(rawArgs)
		if filePath == "" {
			setPendingChangePic(target, strings.TrimSpace(message.GetMessageFrom()), true)
			_ = c.SendMessage(ctx, target, "Send your image.")
			return
		}
		targets := runningSelfbotTargets(c)
		if len(targets) == 0 {
			_ = c.SendMessage(ctx, target, "selfchangepic failed: no running selfbot target")
			return
		}

		success := 0
		lastErr := ""
		for _, bot := range targets {
			botCID := strings.TrimSpace(bot.CurrentCID())
			if botCID == "" {
				botCID = strings.TrimSpace(bot.CID)
			}
			if botCID == "" {
				continue
			}

			uploaded, err := bot.UploadMedia(ctx, filePath, "profile", botCID)
			if err != nil {
				lastErr = err.Error()
				continue
			}
			if _, err := bot.UpdateProfile(ctx, map[string]string{
				"picture_profile": strings.TrimSpace(uploaded.URL),
				"video_profile":   "",
			}, nil); err != nil {
				lastErr = err.Error()
				continue
			}
			success++
		}

		if success == 0 {
			if lastErr == "" {
				lastErr = "unknown error"
			}
			_ = c.SendMessage(ctx, target, "selfchangepic failed: "+lastErr)
			return
		}

		msg := fmt.Sprintf("selfchangepic success: updated %d/%d selfbot", success, len(targets))
		if lastErr != "" && success < len(targets) {
			msg += " (last error: " + lastErr + ")"
		}
		_ = c.SendMessage(ctx, target, msg)
	} else if command == "flexcmd" {
		if strings.TrimSpace(rawArgs) == "" {
			if err := c.SendFlexMessage(ctx, target, defaultVFlexTemplateJSON, "Halo Flex"); err != nil {
				_ = c.SendMessage(ctx, target, "flex failed: "+err.Error())
			}
			return
		}
		altText, flexJSON, err := parseFlexCommandArgs(rawArgs)
		if err != nil {
			_ = c.SendMessage(ctx, target, "flex failed: "+err.Error())
			return
		}
		if err := c.SendFlexMessage(ctx, target, flexJSON, altText); err != nil {
			_ = c.SendMessage(ctx, target, "flex failed: "+err.Error())
			return
		}
	} else if command == "flexcarousel" {
		if err := c.SendFlexMessage(ctx, target, defaultVFlexCarouselTemplateJSON, "VFlex Carousel Demo"); err != nil {
			_ = c.SendMessage(ctx, target, "flexcarousel failed: "+err.Error())
			return
		}
	} else if command == "flexstack" {
		if err := c.SendFlexMessage(ctx, target, defaultVFlexStackDemoJSON, "VFlex Stack Demo"); err != nil {
			_ = c.SendMessage(ctx, target, "flexstack failed: "+err.Error())
			return
		}
	} else if command == "flexshop" {
		if err := c.SendFlexMessage(ctx, target, defaultVFlexShopDemoJSON, "VFlex Shop Demo"); err != nil {
			_ = c.SendMessage(ctx, target, "flexshop failed: "+err.Error())
			return
		}
	} else if command == "flexmenu" {
		if err := c.SendFlexMessage(ctx, target, defaultVFlexMenuDemoJSON, "VFlex Menu Demo"); err != nil {
			_ = c.SendMessage(ctx, target, "flexmenu failed: "+err.Error())
			return
		}
	} else if command == "flexnews" {
		if err := c.SendFlexMessage(ctx, target, defaultVFlexNewsDemoJSON, "VFlex News Demo"); err != nil {
			_ = c.SendMessage(ctx, target, "flexnews failed: "+err.Error())
			return
		}
	} else if command == "flexevent" {
		if err := c.SendFlexMessage(ctx, target, defaultVFlexEventDemoJSON, "VFlex Event Demo"); err != nil {
			_ = c.SendMessage(ctx, target, "flexevent failed: "+err.Error())
			return
		}
	} else if command == "flexcopy" {
		if err := c.SendFlexMessage(ctx, target, defaultVFlexCopyDemoJSON, "VFlex Copy Demo"); err != nil {
			_ = c.SendMessage(ctx, target, "flexcopy failed: "+err.Error())
			return
		}
	} else if command == "flexprofile" {
		if err := c.SendFlexMessage(ctx, target, defaultVFlexProfileDemoJSON, "VFlex Profile Demo"); err != nil {
			_ = c.SendMessage(ctx, target, "flexprofile failed: "+err.Error())
			return
		}
	} else if command == "flexcomplex" {
		if err := c.SendFlexMessage(ctx, target, defaultVFlexComplexDemoJSON, "VFlex Complex Demo"); err != nil {
			_ = c.SendMessage(ctx, target, "flexcomplex failed: "+err.Error())
			return
		}
	} else if command == "flexyoutube" || command == "flexvideo" {
		if err := c.SendFlexMessage(ctx, target, defaultVFlexYouTubeDemoJSON, "VFlex YouTube Style Demo"); err != nil {
			_ = c.SendMessage(ctx, target, "flexyoutube failed: "+err.Error())
			return
		}
	} else if command == "flexspotify" || command == "flexaudio" {
		if err := c.SendFlexMessage(ctx, target, defaultVFlexSpotifyDemoJSON, "VFlex Spotify Style Demo"); err != nil {
			_ = c.SendMessage(ctx, target, "flexspotify failed: "+err.Error())
			return
		}
	} else if command == "me" {
		targetCID := strings.TrimSpace(strings.Join(args, " "))
		if targetCID == "" {
			targetCID = strings.TrimSpace(message.GetMessageFrom())
		}
		if targetCID == "" {
			_ = c.SendMessage(ctx, target, "me failed: target cid is empty")
			return
		}
		altText, flexJSON, err := c.BuildProfileVFlex(ctx, targetCID)
		if err != nil {
			_ = c.SendMessage(ctx, target, "me failed: "+err.Error())
			return
		}
		if err := c.SendFlexMessage(ctx, target, flexJSON, altText); err != nil {
			_ = c.SendMessage(ctx, target, "me failed: "+err.Error())
			return
		}
		if err := c.SendContact(ctx, target, targetCID); err != nil {
			contacts, contactErr := c.GetContacts(ctx, []string{targetCID})
			if contactErr != nil || len(contacts) == 0 || contacts[0] == nil {
				_ = c.SendMessage(ctx, target, "me contact failed: "+err.Error())
				return
			}
			contact := contacts[0]
			_ = c.SendMessage(
				ctx,
				target,
				fmt.Sprintf(
					"contact: cid=%s display_name=%s status=%s",
					strings.TrimSpace(contact.GetCid()),
					strings.TrimSpace(contact.GetDisplayName()),
					strings.TrimSpace(contact.GetStatusMessage()),
				),
			)
		}
	} else if command == "help" {
		commands, err := loadCommands()
		if err != nil {
			_ = c.SendMessage(ctx, target, "help failed: "+err.Error())
			return
		}
		var help strings.Builder
		help.WriteString("Available commands:\n\n")
		keys := make([]string, 0, len(commands))
		for k := range commands {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, cmd := range keys {
			help.WriteString(fmt.Sprintf("  %-12s - %s\n", cmd, commands[cmd]))
		}
		help.WriteString("\nUsage: <command> [args]")
		_ = c.SendMessage(ctx, target, help.String())
	} else if strings.HasPrefix(commandLine, "here") {
		if message.GetMessageType() != pb.MessageType_MessageType_Group {
			_ = c.SendMessage(ctx, target, "This command is only available in group.")
			return
		}
		senderCID := strings.TrimSpace(message.GetMessageFrom())
		filterBotClients := func(clients []*Client) []*Client {
			seen := make(map[string]struct{}, len(clients))
			out := make([]*Client, 0, len(clients))
			for _, cl := range clients {
				if cl == nil {
					continue
				}
				cid := strings.TrimSpace(cl.CurrentCID())
				if cid == "" {
					cid = strings.TrimSpace(cl.CID)
				}
				if cid == "" {
					continue
				}
				// Selfbot must not be treated as bot in "here" command.
				if isSelfbotCID(cid) || cid == senderCID {
					continue
				}
				if _, ok := seen[cid]; ok {
					continue
				}
				seen[cid] = struct{}{}
				out = append(out, cl)
			}
			return out
		}
		allBotClients := func() []*Client {
			clients := snapshotPeerClients()
			if len(clients) == 0 {
				clients = make([]*Client, 0, len(Mclient))
				for _, cl := range Mclient {
					clients = append(clients, cl)
				}
			}
			return filterBotClients(clients)
		}
		refreshGroupBotClients := func(actor *Client) ([]*Client, *VagueRoom) {
			if actor == nil {
				actor = c
			}
			actor.GetSquad(target)
			room := GetRoom(target)
			return filterBotClients(room.Client), room
		}

		bk, room := refreshGroupBotClients(c)
		if commandLine == "here" {
			name := fmt.Sprintf("%v/%v bot's here.", len(bk), len(allBotClients()))
			_ = c.SendMessage(ctx, target, name)
		} else {
			nums := strings.SplitN(commandLine, "here", 2)
			if len(nums) < 2 {
				_ = c.SendMessage(ctx, target, "Usage: here <number>")
				return
			}
			st := StripOut(nums[1])
			numb, err := strconv.Atoi(st)
			if err != nil || numb < 0 {
				_ = c.SendMessage(ctx, target, "Usage: here <number>")
				return
			}
			client := c
			// Keep selfbot as controller for "here" when available,
			// then fallback to any bot in group if needed.
			if client == nil || !client.IsSelfbotClient() {
				for _, cl := range bk {
					if cl != nil {
						client = cl
						break
					}
				}
			}
			client.GetSquad(target)
			bk, room = refreshGroupBotClients(client)
			aa := len(bk)
			left := []string{}
			if aa > numb {
				c := aa - numb
				ca := 0
				list := append([]*Client{}, bk...)
				for _, o := range list {
					_ = o.LeaveGroup(ctx, target)
					left = append(left, o.CID)
					ca = ca + 1
					if ca == c {
						break
					}
				}
				for _, cl := range bk {
					if !Contains(left, cl.CID) {
						aa := cl.GetSquad(target)
						if len(aa) != 0 {
							break
						}
					}
				}

			} else if aa < numb {
				all := []*Client{}
				cuk := bk
				for _, x := range allBotClients() {
					if !InArrayCl(cuk, x) {
						all = append(all, x)
					}
				}
				g := numb - aa
				lim := []string{}
				controllers := []*Client{}
				if c != nil {
					controllers = append(controllers, c)
				}
				controllers = append(controllers, bk...)
				for _, cl := range controllers {
					if cl == nil {
						continue
					}
					_, room.Link, _ = cl.GenerateGroupURL(ctx, target)
					if room.Link == "" {
						lim = append(lim, cl.CID)
					} else {
						room.Clink = cl
						client = cl
						break
					}
				}

				if len(room.Link) == 0 {
					_ = c.SendMessage(ctx, target, "All bot request block..")
					return
				}

				wi := filterBotClients(client.GetSquad(target))
				room.Actor = []*Client{}
				room.Qr = true
				room.Lbackup = client.CID
				for i := 0; i < len(all); i++ {
					if i == g {
						break
					}
					l := all[i]
					if l != client && !InArrayCl(wi, l) {
						room.Actor = append(room.Actor, l)
					}
				}
				_ = client.UpdateGroupJoinByTicket(ctx, target, true)
				for _, cl := range room.Actor {
					go cl.JoinGroupByURL(ctx, room.Link)
				}
				time.Sleep(1 * time.Second)
				room.Qr = false
				_ = client.UpdateGroupJoinByTicket(ctx, target, false)
				bk, room = refreshGroupBotClients(client)
				for _, cl := range bk {
					if !Contains(left, cl.CID) {
						aa := cl.GetSquad(target)
						if len(aa) != 0 {
							break
						}
					}
				}
			} else {
				bk, _ = refreshGroupBotClients(c)
				name := fmt.Sprintf("%v/%v bot's here.", len(bk), len(allBotClients()))
				_ = c.SendMessage(ctx, target, name)
			}
		}
		room.Reset()
	} else if commandLine == "leave" {
		c.GetSquad(target)
		room := GetRoom(target)
		bk := room.Client
		for _, cl := range bk {
			if cl.IsSelfbotClient() {
				continue
			}
			go cl.LeaveGroup(ctx, target)
		}
		Protected = Remove(Protected, target)
		room.Client = []*Client{}
	} else if strings.HasPrefix(commandLine, "kick") {
		if message.GetMessageType() != pb.MessageType_MessageType_Group {
			_ = c.SendMessage(ctx, target, "This command is only available in group.")
			return
		}
		cons := MentionList(message)
		fmt.Println("Mention:", cons)
		room := GetRoom(target)
		if len(cons) != 0 {
			for _, sss := range cons {
				go func(target string) {
					_ = c.RemoveMember(ctx, target, sss)
					if !Contains(Squad, target) {
						AddBan(target, room)
					}
				}(target)
			}
		} else {
			_ = c.SendMessage(ctx, target, "Target not found")
		}
	}
}
