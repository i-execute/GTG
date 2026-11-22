//go:build integration

package client

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/i-execute/GTG/internal/bootstrap"
	"github.com/i-execute/GTG/internal/tlgen"
	"github.com/i-execute/GTG/session"
	"github.com/i-execute/GTG/tl"
)

func TestLiveBotSession(t *testing.T) {
	if os.Getenv("GTG_LIVE") != "1" {
		t.Skip("set GTG_LIVE=1 to enable live bot checks")
	}
	token := []byte(os.Getenv("GTG_BOT_TOKEN"))
	apiHash := []byte(os.Getenv("GTG_API_HASH"))
	apiID, err := strconv.Atoi(os.Getenv("GTG_API_ID"))
	if err != nil || len(token) == 0 || len(apiHash) == 0 || apiID <= 0 {
		clear(token)
		clear(apiHash)
		t.Skip("live bot environment is incomplete")
	}
	defer clear(token)
	defer clear(apiHash)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	result, err := bootstrap.CreateAuthKeyDC(ctx, "149.154.167.50:443", bootstrap.Intermediate, false, 2)
	if err != nil {
		t.Fatal("bootstrap failed")
	}
	defer clear(result.AuthKey)
	config := Config{Endpoint: result.Endpoint, Transport: Transport(result.Transport), AuthKey: append([]byte(nil), result.AuthKey...), ServerSalt: result.ServerSalt, TimeOffset: result.TimeOffset, APIID: apiID, APIHash: append([]byte(nil), apiHash...), DeviceModel: "GTG live check", SystemVersion: "Go", AppVersion: "0.2-next", Language: "en"}
	_ = result.Close()
	client, err := Dial(ctx, config)
	clear(config.AuthKey)
	clear(config.APIHash)
	if err != nil {
		t.Fatal("encrypted dial failed")
	}
	defer client.Close()
	if _, err := client.AuthorizeBot(ctx, token); err != nil {
		t.Fatalf("bot authorization failed: %v", err)
	}
	if _, err := client.GetMe(ctx); err != nil {
		t.Fatal("getMe failed")
	}
	if _, err := client.Call(ctx, tlgen.NewMethodHelpGetConfig_C4F9186B().Request()); err != nil {
		t.Fatal("typed config failed")
	}
	if _, err := client.Call(ctx, tl.Dynamic{Name: "help.getConfig", Fields: map[string]any{}}); err != nil {
		t.Fatal("dynamic config failed")
	}
	account := session.Account{Kind: session.BotAccount, DCID: 2, DCs: []session.DC{{ID: 2, Address: "149.154.167.50", Port: 443}}, AuthKey: append([]byte(nil), result.AuthKey...), ServerSalt: result.ServerSalt, TimeOffset: result.TimeOffset, APIID: int32(apiID), BotToken: append([]byte(nil), token...), Layer: int32(tlgen.Layer), Updates: session.Updates{Channels: make(map[int64]int32)}}
	store := session.NewStore()
	if err := store.Put("bot", account); err != nil {
		account.Destroy()
		store.Destroy()
		t.Fatal(err)
	}
	account.Destroy()
	digest := sha256.Sum256(token)
	credential, err := session.NewRawCredential(digest[:])
	clear(digest[:])
	if err != nil {
		store.Destroy()
		t.Fatal(err)
	}
	encoded, err := store.Marshal(credential)
	store.Destroy()
	credential.Destroy()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(encoded)
	digest = sha256.Sum256(token)
	credential, err = session.NewRawCredential(digest[:])
	clear(digest[:])
	if err != nil {
		t.Fatal(err)
	}
	restored, err := session.OpenStore(encoded, credential)
	credential.Destroy()
	if err != nil {
		t.Fatal("session restore failed")
	}
	defer restored.Destroy()
	_, restoredAccount, err := restored.Active()
	if err != nil {
		t.Fatal(err)
	}
	defer restoredAccount.Destroy()
	restoredConfig, err := ConfigFromAccount(restoredAccount, apiID, apiHash)
	if err != nil {
		t.Fatal(err)
	}
	restoredClient, err := Dial(ctx, restoredConfig)
	clear(restoredConfig.AuthKey)
	clear(restoredConfig.APIHash)
	if err != nil {
		t.Fatal("restored encrypted dial failed")
	}
	defer restoredClient.Close()
	if _, err := restoredClient.GetMe(ctx); err != nil {
		t.Fatal("restored getMe failed")
	}
	if os.Getenv("GTG_LIVE_MESSAGES") == "1" {
		runLiveMessageCheck(t, ctx, restoredClient)
	}
}

func runLiveMessageCheck(t *testing.T, ctx context.Context, client *Client) {
	chatID, err := strconv.ParseInt(os.Getenv("GTG_CHAT_ID"), 10, 64)
	if err != nil || chatID == 0 {
		t.Skip("live chat identifier is unavailable")
	}
	peer, resolved := livePeer(ctx, client, chatID)
	directFallback := false
	if !resolved {
		if chatID < 1 {
			t.Skip("target chat is not present in authorized dialogs; send the bot a message and rerun")
		}
		peer = tlgen.ConstructorInputPeerUser_DDE8A54C{FUserId1: chatID, FAccessHash2: 0}.Dynamic()
		directFallback = true
	}
	_ = cleanupLiveMessages(ctx, client, peer)
	var random [8]byte
	if _, err := rand.Read(random[:]); err != nil {
		t.Fatal(err)
	}
	messageText := "GTG live verification"
	result, err := client.Call(ctx, tlgen.MethodMessagesSendMessage_FEF48F62{FPeer10: peer, FMessage12: messageText, FRandomId13: int64(binary.LittleEndian.Uint64(random[:]))}.Request())
	clear(random[:])
	if err != nil {
		if directFallback {
			t.Skip("target user access hash is unavailable in authorized dialogs; send the bot a message and rerun")
		}
		t.Fatal("sendMessage failed")
	}
	messageID, ok := dynamicMessageID(result)
	if !ok {
		_ = cleanupLiveMessages(context.Background(), client, peer)
		t.Fatal("sendMessage response omitted message id")
	}
	deleted := false
	defer func() {
		if !deleted {
			_, _ = client.Call(context.Background(), tlgen.MethodMessagesDeleteMessages_E58E95D2{FRevoke2: true, FId3: []any{messageID}}.Request())
		}
	}()
	edited := "GTG live verification updated"
	if _, err := client.Call(ctx, tlgen.MethodMessagesEditMessage_B106E66C{FPeer4: peer, FId5: messageID, FMessage6: &edited}.Request()); err != nil {
		t.Fatal("editMessage failed")
	}
	time.Sleep(300 * time.Millisecond)
	if _, err := client.Call(ctx, tlgen.MethodMessagesDeleteMessages_E58E95D2{FRevoke2: true, FId3: []any{messageID}}.Request()); err != nil {
		t.Fatal("deleteMessages failed")
	}
	deleted = true
	_ = cleanupLiveMessages(ctx, client, peer)
}

func cleanupLiveMessages(ctx context.Context, client *Client, peer tl.Dynamic) error {
	result, err := client.Call(ctx, tlgen.MethodMessagesGetHistory_4423E6C5{FPeer1: peer, FLimit5: 20}.Request())
	if err != nil {
		return err
	}
	ids := make([]any, 0, 4)
	collectLiveMessageIDs(result, &ids)
	if len(ids) == 0 {
		return nil
	}
	_, err = client.Call(ctx, tlgen.MethodMessagesDeleteMessages_E58E95D2{FRevoke2: true, FId3: ids}.Request())
	return err
}

func collectLiveMessageIDs(value tl.Dynamic, ids *[]any) {
	if value.Name == "message" {
		text, textOK := value.Fields["message"].(string)
		id, idOK := value.Fields["id"].(int32)
		if textOK && idOK && (text == "GTG live verification" || text == "GTG live verification updated") {
			*ids = append(*ids, id)
		}
	}
	for _, raw := range value.Fields {
		switch item := raw.(type) {
		case tl.Dynamic:
			collectLiveMessageIDs(item, ids)
		case []any:
			for _, element := range item {
				if nested, ok := element.(tl.Dynamic); ok {
					collectLiveMessageIDs(nested, ids)
				}
			}
		}
	}
}

func livePeer(ctx context.Context, client *Client, target int64) (tl.Dynamic, bool) {
	result, err := client.Call(ctx, tlgen.MethodMessagesGetDialogs_A0F4CB4F{FOffsetPeer6: tlgen.NewConstructorInputPeerEmpty_7F3B18EA().Dynamic(), FLimit7: 100}.Request())
	if err != nil {
		return tl.Dynamic{}, false
	}
	if users, ok := result.Fields["users"].([]any); ok {
		for _, raw := range users {
			user, ok := raw.(tl.Dynamic)
			if !ok || user.Name != "user" {
				continue
			}
			id, idOK := user.Fields["id"].(int64)
			hash, hashOK := user.Fields["access_hash"].(int64)
			if idOK && hashOK && id == target {
				return tlgen.ConstructorInputPeerUser_DDE8A54C{FUserId1: id, FAccessHash2: hash}.Dynamic(), true
			}
		}
	}
	if chats, ok := result.Fields["chats"].([]any); ok {
		for _, raw := range chats {
			chat, ok := raw.(tl.Dynamic)
			if !ok {
				continue
			}
			id, idOK := chat.Fields["id"].(int64)
			if !idOK {
				continue
			}
			if chat.Name == "chat" && (id == target || -id == target) {
				return tlgen.ConstructorInputPeerChat_35A95CB9{FChatId1: id}.Dynamic(), true
			}
			if chat.Name == "channel" {
				hash, hashOK := chat.Fields["access_hash"].(int64)
				if hashOK && (id == target || -(1000000000000+id) == target) {
					return tlgen.ConstructorInputPeerChannel_27BCBBFC{FChannelId1: id, FAccessHash2: hash}.Dynamic(), true
				}
			}
		}
	}
	return tl.Dynamic{}, false
}

func dynamicMessageID(value tl.Dynamic) (int32, bool) {
	if value.Name == "updateShortSentMessage" || value.Name == "updateMessageID" {
		id, ok := value.Fields["id"].(int32)
		return id, ok
	}
	if value.Name == "updateNewMessage" || value.Name == "updateNewChannelMessage" {
		message, ok := value.Fields["message"].(tl.Dynamic)
		if !ok {
			return 0, false
		}
		id, ok := message.Fields["id"].(int32)
		return id, ok
	}
	for _, raw := range value.Fields {
		switch item := raw.(type) {
		case tl.Dynamic:
			if id, ok := dynamicMessageID(item); ok {
				return id, true
			}
		case []any:
			for _, element := range item {
				if nested, ok := element.(tl.Dynamic); ok {
					if id, ok := dynamicMessageID(nested); ok {
						return id, true
					}
				}
			}
		}
	}
	return 0, false
}
