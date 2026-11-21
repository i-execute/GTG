package auth

import (
	"context"
	"crypto/rand"
	"errors"
	"math"
	"strings"

	"github.com/i-execute/GTG/core"
	"github.com/i-execute/GTG/internal/tlgen"
	"github.com/i-execute/GTG/tl"
)

var ErrFlow = errors.New("gtg: invalid authorization flow request")

type Caller interface {
	Call(context.Context, tl.Dynamic) (tl.Dynamic, error)
}

type Flow struct {
	call    Caller
	apiID   int32
	apiHash []byte
}

func NewFlow(call Caller, apiID int, apiHash []byte) (*Flow, error) {
	if call == nil || apiID <= 0 || apiID > math.MaxInt32 || len(apiHash) == 0 {
		return nil, ErrFlow
	}
	return &Flow{call: call, apiID: int32(apiID), apiHash: append([]byte(nil), apiHash...)}, nil
}

func (x *Flow) Close() {
	if x == nil {
		return
	}
	clear(x.apiHash)
	x.apiHash = nil
	x.call = nil
	x.apiID = 0
}

func (x *Flow) SendCode(ctx context.Context, phone string) (tl.Dynamic, error) {
	if x == nil || x.call == nil || !validPhone(phone) || len(x.apiHash) == 0 {
		return tl.Dynamic{}, ErrFlow
	}
	settings := tlgen.NewConstructorCodeSettings_AD253D78().Dynamic()
	return x.call.Call(ctx, tlgen.MethodAuthSendCode_A677244F{
		FPhoneNumber1: phone,
		FApiId2:       x.apiID,
		FApiHash3:     string(x.apiHash),
		FSettings4:    settings,
	}.Request())
}

func (x *Flow) SignIn(ctx context.Context, phone, codeHash string, code []byte) (tl.Dynamic, error) {
	if x == nil || x.call == nil || !validPhone(phone) || codeHash == "" || len(code) == 0 || len(code) > 128 {
		return tl.Dynamic{}, ErrFlow
	}
	copyCode := append([]byte(nil), code...)
	defer clear(copyCode)
	text := string(copyCode)
	return x.call.Call(ctx, tlgen.MethodAuthSignIn_8D52A951{
		FFlags1:         1,
		FPhoneNumber2:   phone,
		FPhoneCodeHash3: codeHash,
		FPhoneCode4:     &text,
	}.Request())
}

func (x *Flow) SignUp(ctx context.Context, phone, codeHash, firstName, lastName string) (tl.Dynamic, error) {
	if x == nil || x.call == nil || !validPhone(phone) || codeHash == "" || strings.TrimSpace(firstName) == "" {
		return tl.Dynamic{}, ErrFlow
	}
	return x.call.Call(ctx, tlgen.MethodAuthSignUp_AAC7B717{
		FFlags1:         0,
		FPhoneNumber3:   phone,
		FPhoneCodeHash4: codeHash,
		FFirstName5:     firstName,
		FLastName6:      lastName,
	}.Request())
}

func (x *Flow) CheckPassword(ctx context.Context, password []byte) (tl.Dynamic, error) {
	if x == nil || x.call == nil || len(password) == 0 {
		return tl.Dynamic{}, ErrFlow
	}
	account, err := x.call.Call(ctx, tlgen.NewMethodAccountGetPassword_548A30F5().Request())
	if err != nil {
		return tl.Dynamic{}, err
	}
	parameters, err := passwordParameters(account)
	if err != nil {
		return tl.Dynamic{}, err
	}
	defer destroyParameters(&parameters)
	private := make([]byte, len(parameters.Prime))
	if _, err := rand.Read(private); err != nil {
		clear(private)
		return tl.Dynamic{}, err
	}
	defer clear(private)
	copyPassword := append([]byte(nil), password...)
	defer clear(copyPassword)
	proof, err := core.BuildSRPProof(parameters, string(copyPassword), private)
	if err != nil {
		return tl.Dynamic{}, err
	}
	defer clear(proof.A)
	m1 := append([]byte(nil), proof.M1[:]...)
	defer clear(m1)
	input := tlgen.ConstructorInputCheckPasswordSRP_D27FF082{FSrpId1: proof.ID, FA2: append([]byte(nil), proof.A...), FM13: m1}.Dynamic()
	defer clear(input.Fields["A"].([]byte))
	return x.call.Call(ctx, tlgen.MethodAuthCheckPassword_D18B4D16{FPassword1: input}.Request())
}

func (x *Flow) LogOut(ctx context.Context) (tl.Dynamic, error) {
	if x == nil || x.call == nil {
		return tl.Dynamic{}, ErrFlow
	}
	return x.call.Call(ctx, tlgen.NewMethodAuthLogOut_3E72BA19().Request())
}

func passwordParameters(value tl.Dynamic) (core.SRPParameters, error) {
	account, ok := tlgen.ConstructorAccountPassword_957B50FBFromDynamic(value)
	if !ok || !account.FHasPassword4 || account.FCurrentAlgo5 == nil || account.FSrpB6 == nil || account.FSrpId7 == nil {
		return core.SRPParameters{}, ErrFlow
	}
	algorithm, ok := tlgen.ConstructorPasswordKdfAlgoSHA256SHA256PBKDF2HMACSHA512iter100000SHA256ModPow_3A912D4AFromDynamic(*account.FCurrentAlgo5)
	if !ok {
		return core.SRPParameters{}, ErrFlow
	}
	parameters := core.SRPParameters{
		ID:        *account.FSrpId7,
		Generator: int(algorithm.FG3),
		Prime:     append([]byte(nil), algorithm.FP4...),
		Salt1:     append([]byte(nil), algorithm.FSalt11...),
		Salt2:     append([]byte(nil), algorithm.FSalt22...),
		PublicB:   append([]byte(nil), (*account.FSrpB6)...),
	}
	if err := core.ValidateSafePrime(parameters.Prime, parameters.Generator); err != nil {
		destroyParameters(&parameters)
		return core.SRPParameters{}, err
	}
	if err := core.ValidateDHPublic(parameters.Prime, parameters.PublicB); err != nil {
		destroyParameters(&parameters)
		return core.SRPParameters{}, err
	}
	return parameters, nil
}

func destroyParameters(value *core.SRPParameters) {
	if value == nil {
		return
	}
	clear(value.Prime)
	clear(value.Salt1)
	clear(value.Salt2)
	clear(value.PublicB)
	*value = core.SRPParameters{}
}

func validPhone(value string) bool {
	if len(value) < 3 || len(value) > 32 {
		return false
	}
	for index, r := range value {
		if r == '+' && index == 0 {
			continue
		}
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func clear(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
