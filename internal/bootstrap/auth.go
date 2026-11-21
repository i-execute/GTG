package bootstrap

import (
	"context"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"errors"
	"io"
	"time"

	"github.com/i-execute/GTG/core"
)

var ErrAuth = errors.New("gtg: bootstrap authorization failed")

type authFailureError struct {
	stage string
}

func (x authFailureError) Error() string {
	return "gtg: bootstrap authorization failed"
}

func (x authFailureError) Unwrap() error {
	return ErrAuth
}

func authFailure(stage string) error {
	return authFailureError{stage: stage}
}

type AuthResult struct {
	AuthKey      []byte
	ServerSalt   [8]byte
	TimeOffset   int64
	Fingerprint  uint64
	ServerTime   int64
	Transport    Transport
	Endpoint     string
	IsTestServer bool
	connection   *Connection
}

func (x *AuthResult) Close() error {
	if x == nil || x.connection == nil {
		return nil
	}
	err := x.connection.Close()
	x.connection = nil
	return err
}

type messageIDs struct {
	last uint64
}

func (x *messageIDs) next(now time.Time) uint64 {
	seconds := uint64(now.Unix())
	fraction := uint64(now.Nanosecond()) << 32 / 1_000_000_000
	value := (seconds<<32 | fraction) &^ 3
	if value <= x.last {
		value = x.last + 4
	}
	x.last = value
	return value
}

func CreateAuthKey(ctx context.Context, endpoint string, transport Transport, test bool) (AuthResult, error) {
	return CreateAuthKeyDC(ctx, endpoint, transport, test, 1)
}

func CreateAuthKeyDC(ctx context.Context, endpoint string, transport Transport, test bool, dcID int32) (AuthResult, error) {
	if dcID <= 0 {
		return AuthResult{}, ErrAuth
	}
	keys, err := KnownServerKeys(test)
	if err != nil {
		return AuthResult{}, ErrAuth
	}
	return createAuthKey(ctx, endpoint, transport, test, dcID, keys, rand.Reader)
}

func createAuthKey(ctx context.Context, endpoint string, transport Transport, test bool, dcID int32, keys []core.RSAPublicKey, source io.Reader) (AuthResult, error) {
	stage := "setup"
	if len(keys) == 0 || source == nil {
		return AuthResult{}, authFailure(stage)
	}
	stage = "dial"
	connection, err := Dial(ctx, endpoint, transport)
	if err != nil {
		return AuthResult{}, err
	}
	retainedConnection := false
	defer func() {
		if !retainedConnection {
			_ = connection.Close()
		}
	}()
	deadline := time.Now().Add(30 * time.Second)
	if value, ok := ctx.Deadline(); ok && value.Before(deadline) {
		deadline = value
	}
	if err := connection.SetDeadline(deadline); err != nil {
		return AuthResult{}, err
	}
	ids := messageIDs{}
	var nonce [16]byte
	if _, err := io.ReadFull(source, nonce[:]); err != nil {
		return AuthResult{}, authFailure(stage)
	}
	stage = "req_pq_multi"
	body, err := exchangePlain(connection, &ids, encodeReqPQ(nonce))
	if err != nil {
		return AuthResult{}, err
	}
	stage = "res_pq"
	response, err := decodeResPQ(body)
	clear(body)
	if err != nil || subtle.ConstantTimeCompare(response.nonce[:], nonce[:]) != 1 {
		clearResPQ(&response)
		return AuthResult{}, authFailure(stage)
	}
	stage = "factor_pq"
	p, q, err := core.FactorPQBytes(response.pq)
	if err != nil {
		clearResPQ(&response)
		return AuthResult{}, authFailure(stage)
	}
	stage = "rsa_key"
	key, fingerprint, ok := chooseKey(keys, response.fingerprints)
	if !ok {
		clear(p)
		clear(q)
		clearResPQ(&response)
		return AuthResult{}, authFailure(stage)
	}
	var newNonce [32]byte
	if _, err := io.ReadFull(source, newNonce[:]); err != nil {
		clear(p)
		clear(q)
		clearResPQ(&response)
		return AuthResult{}, authFailure(stage)
	}
	if test {
		dcID += 10000
	}
	inner := encodePQInnerDC(response.pq, p, q, nonce, response.serverNonce, newNonce, dcID)
	stage = "rsa_pad"
	encrypted, err := core.RSAEncryptPad(inner, key, source)
	clear(inner)
	if err != nil {
		clear(p)
		clear(q)
		clearResPQ(&response)
		return AuthResult{}, authFailure(stage)
	}
	stage = "req_DH_params"
	body, err = exchangePlain(connection, &ids, encodeReqDH(nonce, response.serverNonce, p, q, fingerprint, encrypted))
	clear(encrypted)
	clear(p)
	clear(q)
	if err != nil {
		clearResPQ(&response)
		return AuthResult{}, err
	}
	stage = "server_DH_params"
	params, err := decodeServerDHParams(body)
	clear(body)
	if err != nil || subtle.ConstantTimeCompare(params.nonce[:], nonce[:]) != 1 || subtle.ConstantTimeCompare(params.serverNonce[:], response.serverNonce[:]) != 1 {
		clearResPQ(&response)
		clearServerDHParams(&params)
		return AuthResult{}, authFailure(stage)
	}
	stage = "temporary_aes"
	material, err := core.DeriveHandshakeTemporaryAES(newNonce[:], response.serverNonce[:])
	if err != nil {
		clearResPQ(&response)
		clearServerDHParams(&params)
		return AuthResult{}, authFailure(stage)
	}
	stage = "server_DH_inner"
	innerServer, err := decryptServerDH(params.answer, material)
	clearServerDHParams(&params)
	if err != nil || subtle.ConstantTimeCompare(innerServer.nonce[:], nonce[:]) != 1 || subtle.ConstantTimeCompare(innerServer.serverNonce[:], response.serverNonce[:]) != 1 {
		clearResPQ(&response)
		clearServerDHInner(&innerServer)
		return AuthResult{}, authFailure(stage)
	}
	stage = "dh_prime"
	if err := core.ValidateTelegramDH(innerServer.prime, int(innerServer.generator)); err != nil {
		clearResPQ(&response)
		clearServerDHInner(&innerServer)
		return AuthResult{}, authFailure(stage)
	}
	stage = "g_a"
	if err := core.ValidateDHPublic(innerServer.prime, innerServer.public); err != nil {
		clearResPQ(&response)
		clearServerDHInner(&innerServer)
		return AuthResult{}, authFailure(stage)
	}
	stage = "g_b_secret"
	secret, err := core.GenerateDHSecret(innerServer.prime, source)
	if err != nil {
		clearResPQ(&response)
		clearServerDHInner(&innerServer)
		return AuthResult{}, authFailure(stage)
	}
	base := []byte{byte(innerServer.generator)}
	stage = "g_b"
	public, err := core.ModExp(base, secret, innerServer.prime)
	if err != nil {
		clear(secret)
		clearResPQ(&response)
		clearServerDHInner(&innerServer)
		return AuthResult{}, authFailure(stage)
	}
	public = pad256(public)
	if len(public) != 256 || core.ValidateDHPublic(innerServer.prime, public) != nil {
		clear(secret)
		clear(public)
		clearResPQ(&response)
		clearServerDHInner(&innerServer)
		return AuthResult{}, authFailure(stage)
	}
	stage = "auth_key"
	authKey, err := core.ComputeDHAuthKey(innerServer.prime, innerServer.public, secret)
	clear(secret)
	if err != nil {
		clear(public)
		clearResPQ(&response)
		clearServerDHInner(&innerServer)
		return AuthResult{}, authFailure(stage)
	}
	clientInner := encodeClientDHInner(nonce, response.serverNonce, 0, public)
	clear(public)
	stage = "client_dh_encrypt"
	encrypted, err = core.EncryptDHAnswer(clientInner, material, source)
	clear(clientInner)
	if err != nil {
		clear(authKey)
		clearResPQ(&response)
		clearServerDHInner(&innerServer)
		return AuthResult{}, authFailure(stage)
	}
	stage = "set_client_DH_params"
	body, err = exchangePlain(connection, &ids, encodeSetClientDH(nonce, response.serverNonce, encrypted))
	clear(encrypted)
	if err != nil {
		clear(authKey)
		clearResPQ(&response)
		clearServerDHInner(&innerServer)
		return AuthResult{}, err
	}
	stage = "dh_gen"
	generated, err := decodeDHGen(body)
	clear(body)
	if err != nil || generated.constructor != constructorDHGenOK || subtle.ConstantTimeCompare(generated.nonce[:], nonce[:]) != 1 || subtle.ConstantTimeCompare(generated.serverNonce[:], response.serverNonce[:]) != 1 {
		clear(authKey)
		clearResPQ(&response)
		clearServerDHInner(&innerServer)
		return AuthResult{}, authFailure(stage)
	}
	stage = "new_nonce_hash"
	expected, err := core.NewNonceHash(newNonce[:], authKey, 1)
	if err != nil || subtle.ConstantTimeCompare(expected[:], generated.newNonce[:]) != 1 {
		clear(expected[:])
		clear(authKey)
		clearResPQ(&response)
		clearServerDHInner(&innerServer)
		return AuthResult{}, authFailure(stage)
	}
	clear(expected[:])
	stage = "server_salt"
	salt, err := core.ServerSalt(newNonce[:], response.serverNonce[:])
	if err != nil {
		clear(authKey)
		clearResPQ(&response)
		clearServerDHInner(&innerServer)
		return AuthResult{}, authFailure(stage)
	}
	result := AuthResult{
		AuthKey:      authKey,
		ServerSalt:   salt,
		TimeOffset:   int64(innerServer.serverTime) - time.Now().Unix(),
		Fingerprint:  fingerprint,
		ServerTime:   int64(innerServer.serverTime),
		Transport:    transport,
		Endpoint:     endpoint,
		IsTestServer: test,
		connection:   connection,
	}
	retainedConnection = true
	clearResPQ(&response)
	clearServerDHInner(&innerServer)
	return result, nil
}

func exchangePlain(connection *Connection, ids *messageIDs, body []byte) ([]byte, error) {
	packet := encodePlain(ids.next(time.Now()), body)
	clear(body)
	if err := connection.WritePacket(packet); err != nil {
		clear(packet)
		return nil, err
	}
	clear(packet)
	response, err := connection.ReadPacket()
	if err != nil {
		return nil, err
	}
	_, result, err := decodePlain(response)
	if err != nil {
		clear(response)
		return nil, authFailure("plain_response")
	}
	out := append([]byte(nil), result...)
	clear(response)
	return out, nil
}

func chooseKey(keys []core.RSAPublicKey, fingerprints []uint64) (core.RSAPublicKey, uint64, bool) {
	for _, key := range keys {
		fingerprint, err := core.RSAFingerprint(key)
		if err != nil {
			continue
		}
		for _, wanted := range fingerprints {
			if fingerprint == wanted {
				return key, fingerprint, true
			}
		}
	}
	return core.RSAPublicKey{}, 0, false
}

func decryptServerDH(ciphertext []byte, material core.TemporaryAES) (serverDHInner, error) {
	var result serverDHInner
	if len(ciphertext) < 32 || len(ciphertext)&15 != 0 {
		return result, ErrAuth
	}
	ige, err := core.NewIGE(material.Key[:])
	if err != nil {
		return result, ErrAuth
	}
	plain := make([]byte, len(ciphertext))
	err = ige.Decrypt(plain, ciphertext, material.IV[:])
	ige.Destroy()
	if err != nil {
		clear(plain)
		return result, ErrAuth
	}
	decoded, consumed, err := decodeServerDHInner(plain[20:])
	if err != nil || consumed <= 0 || 20+consumed > len(plain) {
		clear(plain)
		return result, ErrAuth
	}
	hash := sha1.Sum(plain[20 : 20+consumed])
	valid := subtle.ConstantTimeCompare(hash[:], plain[:20])
	clear(hash[:])
	if valid != 1 {
		clear(plain)
		clearServerDHInner(&decoded)
		return result, ErrAuth
	}
	result = serverDHInner{
		nonce:       decoded.nonce,
		serverNonce: decoded.serverNonce,
		generator:   decoded.generator,
		prime:       append([]byte(nil), decoded.prime...),
		public:      append([]byte(nil), decoded.public...),
		serverTime:  decoded.serverTime,
	}
	clearServerDHInner(&decoded)
	clear(plain)
	return result, nil
}

func pad256(value []byte) []byte {
	if len(value) == 0 || len(value) > 256 {
		clear(value)
		return nil
	}
	out := make([]byte, 256)
	copy(out[256-len(value):], value)
	clear(value)
	return out
}

func clearResPQ(value *resPQ) {
	clear(value.pq)
	clear(value.fingerprints)
	clear(value.nonce[:])
	clear(value.serverNonce[:])
}

func clearServerDHParams(value *serverDHParams) {
	clear(value.answer)
	clear(value.nonce[:])
	clear(value.serverNonce[:])
}

func clearServerDHInner(value *serverDHInner) {
	clear(value.prime)
	clear(value.public)
	clear(value.nonce[:])
	clear(value.serverNonce[:])
	value.generator = 0
	value.serverTime = 0
}
