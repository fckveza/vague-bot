package vaguebot

import (
	"strings"
	pb "vague-bot/proto"
)

func MentionList(msg *pb.Message) []string {
	taglist := []string{}
	if msg.ContentMetadata != nil {
		data, ok := msg.ContentMetadata["mention"]
		if ok {
			aa := strings.Split(data, "@")
			for _, c := range aa {
				if len(c) > 2 {
					taglist = append(taglist, c)
				}
			}
		}
	}
	return taglist
}
func GetToType(to string) pb.MessageType {
	target := strings.ToLower(strings.TrimSpace(to))
	if strings.HasPrefix(target, "c") || strings.HasPrefix(target, "g") || strings.HasPrefix(target, "r") {
		return pb.MessageType_MessageType_Group
	}
	return pb.MessageType_MessageType_Private
}
func getreply(cl *Client, msg *pb.Message) (tx []string, ms []*pb.Message) {
	if msg == nil {
		return tx, ms
	}

	origin := msg.GetOrigin()
	if origin == nil {
		return tx, ms
	}

	if original := origin.GetOriginalMessage(); original != nil {
		if sender := strings.TrimSpace(original.GetMessageFrom()); sender != "" {
			tx = append(tx, sender)
		}
		ms = append(ms, original)
		return tx, ms
	}

	sender := strings.TrimSpace(origin.GetCreator())
	if sender != "" {
		tx = append(tx, sender)
	}
	if sender != "" || strings.TrimSpace(origin.GetOriginalMessageId()) != "" {
		ms = append(ms, &pb.Message{
			MessageId:   strings.TrimSpace(origin.GetOriginalMessageId()),
			MessageFrom: sender,
		})
	}
	return tx, ms
}
