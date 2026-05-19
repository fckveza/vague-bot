package vaguebot

import (
	"fmt"
	"strings"

	pb "vague-bot/proto"
)

func supportedEventTypes() []pb.EventType {
	return []pb.EventType{
		pb.EventType_EVENT_MESSAGE_RECEIVED,
		pb.EventType_EVENT_MESSAGE_SENT,
		pb.EventType_EVENT_MESSAGE_READ,
		pb.EventType_EVENT_MESSAGE_DELETED,
		pb.EventType_EVENT_MESSAGE_EDITED,
		pb.EventType_EVENT_MESSAGE_DELIVERED,
		pb.EventType_EVENT_GROUP_CREATED,
		pb.EventType_EVENT_GROUP_UPDATED,
		pb.EventType_EVENT_SELF_UPDATE_GROUP,
		pb.EventType_EVENT_INVITATION_CANCELED,
		pb.EventType_EVENT_SELF_CANCEL_INVITATION,
		pb.EventType_EVENT_MEMBER_JOINED,
		pb.EventType_EVENT_SELF_JOINED,
		pb.EventType_EVENT_MEMBER_LEFT,
		pb.EventType_EVENT_SELF_LEFT,
		pb.EventType_EVENT_MEMBER_REMOVED,
		pb.EventType_EVENT_SELF_REMOVED,
		pb.EventType_EVENT_MEMBER_INVITED,
		pb.EventType_EVENT_SELF_INVITED,
		pb.EventType_EVENT_REJECTED_INVITATION,
		pb.EventType_EVENT_SELF_REJECTED_INVITATION,
		pb.EventType_EVENT_CONTACT_ADDED,
		pb.EventType_EVENT_SELF_ADDED_CONTACT,
		pb.EventType_EVENT_CONTACT_REMOVED,
		pb.EventType_EVENT_CONTACT_BLOCKED,
		pb.EventType_EVENT_CONTACT_UNBLOCKED,
		pb.EventType_EVENT_USER_STATUS_UPDATED,
		pb.EventType_EVENT_USER_PROFILE_UPDATED,
	}
}

func groupFromEvent(event *pb.StreamEvent) *pb.Group {
	if event == nil {
		return nil
	}
	if update := event.GetUpdateGroup(); update != nil && update.GetGroup() != nil {
		return update.GetGroup()
	}
	return event.GetParam1()
}

func summarizeEventContext(event *pb.StreamEvent) string {
	if event == nil {
		return "event context unavailable"
	}

	group := event.GetParam1()
	actor := event.GetParam2()
	target := event.GetParam3()

	parts := make([]string, 0, 3)
	if group != nil && (group.GetGroupId() != "" || group.GetName() != "") {
		parts = append(parts, fmt.Sprintf("group=%s(%s)", group.GetGroupId(), group.GetName()))
	}
	if actor != nil && (actor.GetCid() != "" || actor.GetDisplayName() != "" || actor.GetSavedName() != "") {
		parts = append(parts, fmt.Sprintf("actor=%s(%s)", actor.GetCid(), firstNonEmpty(actor.GetSavedName(), actor.GetDisplayName())))
	}
	if target != nil && (target.GetCid() != "" || target.GetDisplayName() != "" || target.GetSavedName() != "") {
		parts = append(parts, fmt.Sprintf("target=%s(%s)", target.GetCid(), firstNonEmpty(target.GetSavedName(), target.GetDisplayName())))
	}
	if len(parts) == 0 {
		return "event context unavailable"
	}
	return strings.Join(parts, " ")
}
