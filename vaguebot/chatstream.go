package vaguebot

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"strings"
	"time"

	pb "vague-bot/proto"
)

func (c *Client) ChatStreamMultiEvent(ctx context.Context) error {
	stream, err := c.GrpcClient.ChatStreamMultipleEvent(ctx)
	if err != nil {
		return fmt.Errorf("ChatStreamMultipleEvent rpc: %w", err)
	}
	defer stream.CloseSend()

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
		return fmt.Errorf("send connect request: %w", err)
	}

	done := make(chan struct{})
	defer close(done)
	if c.cfg.PingInterval > 0 {
		go func() {
			ticker := time.NewTicker(c.cfg.PingInterval)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-done:
					return
				case <-ticker.C:
					pingReq := &pb.StreamRequest{
						Request: &pb.StreamRequest_Ping{
							Ping: &pb.PingRequest{Timestamp: time.Now().UnixMilli()},
						},
					}
					if err := stream.Send(pingReq); err != nil {
						if ctx.Err() == nil {
							log.Printf("[%s] stream ping failed: %v", c.CurrentCID(), err)
						}
						return
					}
				}
			}
		}()
	}

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		batch, err := stream.Recv()
		if err != nil {
			if errors.Is(err, io.EOF) {
				_ = c.PersistState()
				return nil
			}
			return fmt.Errorf("stream recv failed: %w", err)
		}
		if batch == nil {
			continue
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
					log.Printf("[%s] received self invite event: %v", c.CurrentCID(), event)

				case pb.EventType_EVENT_MEMBER_INVITED:
					to, pelaku := event.Param1.GroupId, event.Param2.Cid
					invitesCon := event.GetGroupInvite().Target
					invites := []string{}
					for _, con := range invitesCon {
						invites = append(invites, con.Cid)
					}
					if Contains(invites, c.CurrentCID()) {
						c.RespondInvitation(ctx, to, true)
						log.Printf("[%s] auto accepted member invite to group %s from %s", c.CurrentCID(), to, pelaku)
					}
					log.Printf("[%s] received member invite event: %v", c.CurrentCID(), event)

				case pb.EventType_EVENT_MEMBER_REMOVED:
					log.Printf("[%s] received member removed event: %v", c.CurrentCID(), event)

				case pb.EventType_EVENT_MEMBER_JOINED:
					log.Printf("[%s] received member joined event: %v", c.CurrentCID(), event)

				case pb.EventType_EVENT_INVITATION_CANCELED:
					log.Printf("[%s] received invitation canceled event: %v", c.CurrentCID(), event)

				case pb.EventType_EVENT_SELF_UPDATE_GROUP:
					log.Printf("[%s] received self update group event: %v", c.CurrentCID(), event)

				case pb.EventType_EVENT_GROUP_UPDATED:
					log.Printf("[%s] received group updated event: %v", c.CurrentCID(), event)

				case pb.EventType_EVENT_SELF_JOINED:
					log.Printf("[%s] received self joined event: %v", c.CurrentCID(), event)
				case pb.EventType_EVENT_SELF_REMOVED:
					log.Printf("[%s] received self removed event: %v", c.CurrentCID(), event)
				case pb.EventType_EVENT_SELF_CANCEL_INVITATION:
					log.Printf("[%s] received self cancel invitation event: %v", c.CurrentCID(), event)
				case pb.EventType_EVENT_MESSAGE_RECEIVED:
					if Selfbot {
						continue
					}
					message := event.GetMessage()
					plainText, err := c.decryptMessageText(ctx, message)
					if err != nil {
						log.Printf("[%s] failed to decrypt message %s: %v", c.CurrentCID(), message.GetMessageId(), err)
						continue
					}
					c.handleTextCommandIfNeeded(ctx, message, plainText)
				case pb.EventType_EVENT_MESSAGE_SENT:
					if !Selfbot {
						continue
					}
					message := event.GetMessage()
					plainText, err := c.decryptMessageText(ctx, message)
					if err != nil {
						log.Printf("[%s] failed to decrypt message %s: %v", c.CurrentCID(), message.GetMessageId(), err)
						continue
					}
					log.Println(plainText)
					c.handleTextCommandIfNeeded(ctx, message, plainText)

				case pb.EventType_EVENT_CONTACT_ADDED:
					log.Printf("[%s] received contact added event: %v", c.CurrentCID(), event)

				case pb.EventType_EVENT_MEMBER_LEFT:
					log.Printf("[%s] received member left event: %v", c.CurrentCID(), event)

				case pb.EventType_EVENT_MESSAGE_READ:
					log.Printf("[%s] received message read event: %v", c.CurrentCID(), event)
				default:
					log.Printf("[%s] received unknown event type=%v event=%v", c.CurrentCID(), event.GetEventType(), event)
				}
			}
		}
	}
}

func (c *Client) handleTextCommandIfNeeded(ctx context.Context, message *pb.Message, plainText string) {
	if message == nil {
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
	if messageID != "" && !c.markHandledMessage(messageID) {
		return
	}

	target := strings.TrimSpace(message.GetMessageTo())
	if message.GetMessageType() == pb.MessageType_MessageType_Private {
		target = from
	}
	if target == "" {
		return
	}

	command := strings.ToLower(parts[0])
	args := parts[1:]
	switch command {
	case "ping":
		_ = c.SendMessage(ctx, target, "pong")
	case "lastrev":
		revision, err := c.GetLastEventRevision(ctx)
		if err != nil {
			_ = c.SendMessage(ctx, target, "lastrev failed: "+err.Error())
			return
		}
		_ = c.SendMessage(ctx, target, fmt.Sprintf("lastrev: last=%d current=%d session=%s", revision.GetLastEventRevision(), revision.GetCurrentRevision(), revision.GetStreamSessionId()))
	case "lastview":
		revision, err := c.GetLastViewRevision(ctx)
		if err != nil {
			_ = c.SendMessage(ctx, target, "lastview failed: "+err.Error())
			return
		}
		_ = c.SendMessage(ctx, target, fmt.Sprintf("lastview: last=%d current=%d session=%s", revision.GetLastViewRevision(), revision.GetCurrentRevision(), revision.GetStreamSessionId()))
	case "profile":
		profile, err := c.GetProfile(ctx)
		if err != nil {
			_ = c.SendMessage(ctx, target, "profile failed: "+err.Error())
			return
		}
		reply := fmt.Sprintf("profile: cid=%s display_name=%s user_id=%s", profile.GetCid(), profile.GetDisplayName(), profile.GetUserId())
		_ = c.SendMessage(ctx, target, reply)
	case "friends":
		contacts, err := c.GetFriends(ctx)
		if err != nil {
			_ = c.SendMessage(ctx, target, "friends failed: "+err.Error())
			return
		}
		_ = c.SendMessage(ctx, target, fmt.Sprintf("friends: %d %s", len(contacts), summarizeContacts(contacts, 3)))
	case "groups":
		groups, err := c.GetMyGroups(ctx)
		if err != nil {
			_ = c.SendMessage(ctx, target, "groups failed: "+err.Error())
			return
		}
		_ = c.SendMessage(ctx, target, fmt.Sprintf("groups: %d %s", len(groups), summarizeGroups(groups, 3)))
	case "settings":
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
	case "search":
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
		_ = c.SendMessage(ctx, target, fmt.Sprintf("search: cid=%s display_name=%s", contact.GetCid(), contact.GetDisplayName()))
	case "addfriend":
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
	case "contacts":
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
	case "blocked":
		contacts, err := c.GetBlockedUsers(ctx)
		if err != nil {
			_ = c.SendMessage(ctx, target, "blocked failed: "+err.Error())
			return
		}
		_ = c.SendMessage(ctx, target, fmt.Sprintf("blocked: %d %s", len(contacts), summarizeContacts(contacts, 5)))
	case "creategroup":
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
	case "group":
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
		_ = c.SendMessage(ctx, target, fmt.Sprintf("group: id=%s name=%s members=%d", group.GetGroupId(), group.GetName(), memberCount))
	case "groupname":
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
	case "invite":
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
	case "remove":
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
	case "cancelinvite":
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
	case "invitations":
		invitations, err := c.GetMyGroupInvitations(ctx)
		if err != nil {
			_ = c.SendMessage(ctx, target, "invitations failed: "+err.Error())
			return
		}
		_ = c.SendMessage(ctx, target, fmt.Sprintf("invitations: %d %s", len(invitations), summarizeGroups(invitations, 5)))
	case "findinvite":
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
	case "groupurl":
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
	case "joinurl":
		groupID := resolveGroupCommandTarget(message, args)
		if err := c.handleJoinURLCommand(ctx, target, groupID); err != nil {
			_ = c.SendMessage(ctx, target, "joinurl failed: "+err.Error())
		}
	case "leavegroup":
		groupID := resolveGroupCommandTarget(message, args)
		if err := c.LeaveGroup(ctx, groupID); err != nil {
			_ = c.SendMessage(ctx, target, "leavegroup failed: "+err.Error())
			return
		}
		if message.GetMessageType() != pb.MessageType_MessageType_Group {
			_ = c.SendMessage(ctx, target, "leavegroup success: "+groupID)
		}
	case "getmsg":
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
	case "origin":
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
	case "edit":
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
	case "delete":
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
	case "upload":
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
	case "help":
		_ = c.SendMessage(ctx, target, "commands: ping, lastrev, lastview, profile, friends, groups, settings [set k v], search <q>, addfriend <id>, contacts <cid...>, blocked, creategroup <name>|<cid,...>, group <id>, groupname <id>, invite <group> <cid...>, remove <group> <cid>, cancelinvite <group> <cid>, invitations, findinvite <code>, groupurl [group], joinurl [group], leavegroup [group], getmsg <id>, origin <id>, edit <id> <text>, delete <id> [all], upload <path> [category] [target]")
	}
}
