package auth

import (
	"context"
	"testing"

	"github.com/i-execute/GTG/internal/tlgen"
	"github.com/i-execute/GTG/tl"
)

type flowCaller struct {
	requests []tl.Dynamic
	result   tl.Dynamic
}

func (x *flowCaller) Call(ctx context.Context, request tl.Dynamic) (tl.Dynamic, error) {
	x.requests = append(x.requests, request)
	return x.result, nil
}

func TestFlowBuildsGeneratedPhoneRequests(t *testing.T) {
	caller := &flowCaller{result: tl.Dynamic{Name: "auth.sentCode", Fields: map[string]any{}}}
	flow, err := NewFlow(caller, 123, []byte("api-hash"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := flow.SendCode(context.Background(), "+123456789"); err != nil {
		t.Fatal(err)
	}
	request := caller.requests[0]
	if request.Name != "auth.sendCode" || request.Fields["api_id"] != int32(123) || request.Fields["settings"].(tl.Dynamic).Name != "codeSettings" {
		t.Fatal("send code request mismatch")
	}
	if _, err := flow.SignIn(context.Background(), "+123456789", "hash", []byte("12345")); err != nil {
		t.Fatal(err)
	}
	request = caller.requests[1]
	if request.Name != "auth.signIn" || request.Fields["flags"] != int32(1) || request.Fields["phone_code"] != "12345" {
		t.Fatal("sign in request mismatch")
	}
	flow.Close()
	if _, err := flow.SendCode(context.Background(), "+123456789"); err != ErrFlow {
		t.Fatal("closed flow accepted request")
	}
}

func TestFlowPasswordRejectsUnsupportedParameters(t *testing.T) {
	algorithm := tl.Dynamic{Name: "passwordKdfAlgoUnknown", Fields: map[string]any{}}
	public := []byte{1}
	id := int64(3)
	caller := &flowCaller{result: tlgen.ConstructorAccountPassword_957B50FB{
		FHasPassword4:    true,
		FCurrentAlgo5:    &algorithm,
		FSrpB6:           &public,
		FSrpId7:          &id,
		FNewAlgo10:       tl.Dynamic{Name: "passwordKdfAlgoUnknown", Fields: map[string]any{}},
		FNewSecureAlgo11: tl.Dynamic{Name: "securePasswordKdfAlgoUnknown", Fields: map[string]any{}},
	}.Dynamic()}
	flow, err := NewFlow(caller, 123, []byte("api-hash"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := flow.CheckPassword(context.Background(), []byte("password")); err != ErrFlow {
		t.Fatalf("unexpected error %v", err)
	}
	if len(caller.requests) != 1 || caller.requests[0].Name != "account.getPassword" {
		t.Fatal("password request mismatch")
	}
}

func TestValidPhone(t *testing.T) {
	for _, value := range []string{"+123", "123456789"} {
		if !validPhone(value) {
			t.Fatalf("valid phone rejected: %q", value)
		}
	}
	for _, value := range []string{"12", "+", "+12a", "1 23"} {
		if validPhone(value) {
			t.Fatalf("invalid phone accepted: %q", value)
		}
	}
}
