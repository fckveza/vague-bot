package vaguebot

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"
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

func IsBan(user string) bool {
	if Contains(Blacklist, user) {
		return true
	}
	return false
}

type VagueRoom struct {
	Name       string
	Id         string
	Lqr        bool
	Hostage    []string
	Bot        []string
	Client     []*Client
	Actor      []*Client
	Lonte      []string
	Suspect    []string
	Invite     int
	Kick       int
	Cancel     int
	Outsider   int
	LastKick   time.Time
	Fight      time.Time
	SusTime    time.Time
	Kicked     []string
	Qr         bool
	NotifedInv bool
	Danger     bool
	Ajur       bool
	Bajingan   []string
	Tclient    string
	Tcore      []string
	Linv       []string
	Link       string
	Clink      *Client
	Mparam2    string
	Minv       string
	Mkick      string
	Lbackup    string
	LTarget    string
	Here       bool
	Banned     []string
	Leave      time.Time
	LTargets   []string
}

var SquadRoom = []*VagueRoom{}

func GetRoom(to string) *VagueRoom {
	for _, room := range SquadRoom {
		if room.Id == to {
			return room
		}
	}
	new := &VagueRoom{Id: to, Kicked: []string{}, Qr: true, Danger: false, Tclient: "", Mparam2: "", Minv: "", Outsider: 0, Ajur: false}
	SquadRoom = append(SquadRoom, new)
	return new
}
func banAll(memlist []string, room *VagueRoom) {
	ilen := len(memlist)
	for i := 0; i < ilen; i++ {
		AddBan(memlist[i], room)
	}
}
func AddBan(asu string, room *VagueRoom) {
	if !Contains(Squad, asu) {
		if !Contains(Blacklist, asu) {
			Blacklist = append(Blacklist, asu)
			room.Bajingan = append(room.Bajingan, asu)
		}
	}
}

func IsBanArray(s []string) bool {
	for _, user := range s {
		if Contains(Blacklist, user) {
			return true
		}
	}
	return false
}

func Gone(to string, cl *Client, room *VagueRoom, cek bool) {
	if !cl.GetAction(to) {
		cl.Action = append(cl.Action, to)
	}

	if cek {
		if Contains(room.LTargets, cl.CID) {
			room.LTargets = Remove(room.LTargets, cl.CID)
		}
	}
}

func (cl *Client) GetAction(to string) bool {
	return Contains(cl.Action, to)
}

func (cl *Client) AddAction(to string) {
	if !Contains(cl.Action, to) {
		cl.Action = append(cl.Action, to)
	}
}

func (cln *VagueRoom) Reset() {
	cln.Qr = false
	cln.Tcore = []string{}
	cln.Linv = []string{}
	cln.Bajingan = []string{}
	cln.LTarget = ""
	cln.LTargets = []string{}
	cln.SusTime = time.Time{}
	cln.Suspect = []string{}
	cln.Danger = false
	cln.Ajur = false
	cln.Mparam2 = ""
	cln.Tclient = ""
}
func Remove(items []string, item string) []string {
	newitems := []string{}
	for _, i := range items {
		if i != item {
			newitems = append(newitems, i)
		}
	}

	return newitems
}

func (cln *Client) GetChatList(to string) (name string, mem, inv []string) {
	res, err := cln.GetGroup(context.TODO(), to)
	if err != nil {
		log.Println(fmt.Sprintf("GetChatsFCK %v", err))
	}
	if err != nil {
		log.Println(fmt.Sprintf("GetChatsFCK %v", err))
		return name, mem, inv
	}
	if res == nil {
		return name, mem, inv
	}

	for a := range res.Extra.Members {
		mem = append(mem, a)
	}
	for a := range res.Extra.Invitations {
		inv = append(inv, a)
	}
	return res.Name, mem, inv
}

func (cln *VagueRoom) AddSquad(bot []string, cls []*Client) {
	cln.Bot = bot
	cln.Client = cls
}

func InArrayCl(arr []*Client, str *Client) bool {
	for _, tar := range arr {
		if tar == str {
			return true
		}
	}
	return false
}

func StripOut(kata string) string {
	kata = strings.TrimPrefix(kata, " ")
	kata = strings.TrimSuffix(kata, " ")
	return kata
}

func (tok *Client) GetSquad(to string) []*Client {
	nm, memlist, _ := tok.GetChatList(to)
	gmem := []*Client{}
	gs := []string{}
	for _, ym := range memlist {
		if Contains(Squad, ym) {
			gs = append(gs, ym)
			gmem = append(gmem, Mclient[ym])
		}
	}

	room := GetRoom(to)
	room.AddSquad(gs, gmem)
	room.Name = nm
	if !Contains(Protected, to) {
		Protected = append(Protected, to)
	}
	return gmem
}

func (client *Client) SafeClient(to string, param2 string, param3 string, dul bool, room *VagueRoom) {
	var _, memlist, inv = true, map[string]int64{}, map[string]*pb.Invitation{}
	for _, cls := range room.Client {
		if !cls.GetAction(to) {
			_, memlist, inv = cls.GetChatCustom(to)
			if len(memlist) != 0 {
				break
			}
		}
	}
	if len(memlist) == 0 {
		_, memlist, inv = client.GetChatCustom(to)
		if len(memlist) == 0 {
			for _, cls := range room.Client {
				if cls.CID != client.CID {
					_, memlist, inv = cls.GetChatCustom(to)
					if len(memlist) != 0 {
						break
					}
				}
			}
		}
	}
	bot := room.Bot
	var exe = []*Client{}
	oke := []string{}
	ban := []string{}
	for mid := range memlist {
		if Contains(bot, mid) {
			cl := Mclient[mid]
			oke = append(oke, mid)
			exe = append(exe, cl)

		} else if IsBan(mid) {
			if mid != param2 {
				ban = append(ban, mid)
			} else {
				ban = append([]string{param2}, ban...)
			}
		}
	}
	var cl *Client
	if len(exe) != 0 {
		cl = exe[0]
	} else if len(oke) != 0 {
		for _, cm := range oke {
			cl = Mclient[cm]
			break
		}
		return

	} else {
		log.Println("Squad is End")
		return
	}

	for i := range inv {
		if IsBan(i) {
			go func(is string) {
				cl.CancelInvitation(context.TODO(), to, is)
			}(i)
		}
	}

	for _, mid := range ban {
		go func(o string) {
			cl.RemoveMember(context.TODO(), to, o)
		}(mid)
	}
	targetinv := []string{}
	for _, mie := range bot {
		if !Contains(oke, mie) {
			if _, ok := inv[mie]; ok {
				continue
			}
			targetinv = append(targetinv, mie)
		}
	}
	if len(targetinv) != 0 {
		go cl.InviteMember(context.TODO(), to, targetinv)
	}
}