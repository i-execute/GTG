package client

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"strconv"
	"strings"
	"sync"

	"github.com/i-execute/GTG/internal/bootstrap"
	"github.com/i-execute/GTG/internal/tlgen"
	"github.com/i-execute/GTG/tl"
)

var ErrRPC = errors.New("gtg: RPC response rejected")

type Transport uint8

const (
	Abridged Transport = iota
	Intermediate
	PaddedIntermediate
)

type Config struct {
	Endpoint      string
	Transport     Transport
	AuthKey       []byte
	ServerSalt    [8]byte
	TimeOffset    int64
	APIID         int
	APIHash       []byte
	DeviceModel   string
	SystemVersion string
	AppVersion    string
	Language      string
}

type RPCError struct {
	Code      int
	Message   string
	FloodWait int
	MigrateDC int
}

func (x *RPCError) Error() string {
	if x == nil {
		return ""
	}
	return fmt.Sprintf("gtg: RPC %d %s", x.Code, x.Message)
}

type Client struct {
	mu            sync.Mutex
	session       *bootstrap.EncryptedSession
	schema        *tl.Schema
	apiID         int
	apiHash       []byte
	deviceModel   string
	systemVersion string
	appVersion    string
	language      string
	initialized   bool
}

func Dial(ctx context.Context, config Config) (*Client, error) {
	if config.Endpoint == "" || len(config.AuthKey) != 256 {
		return nil, ErrRPC
	}
	session, err := bootstrap.DialExistingAuth(ctx, config.Endpoint, bootstrap.Transport(config.Transport), config.AuthKey, config.ServerSalt, config.TimeOffset)
	if err != nil {
		return nil, err
	}
	return &Client{session: session, schema: tlgen.Schema(), apiID: config.APIID, apiHash: append([]byte(nil), config.APIHash...), deviceModel: config.DeviceModel, systemVersion: config.SystemVersion, appVersion: config.AppVersion, language: config.Language}, nil
}

func (x *Client) Close() error {
	if x == nil {
		return nil
	}
	x.mu.Lock()
	defer x.mu.Unlock()
	if x.session == nil {
		return nil
	}
	err := x.session.Close()
	x.session = nil
	clear(x.apiHash)
	x.apiHash = nil
	return err
}

func (x *Client) Ping(id uint64) error {
	if x == nil {
		return ErrRPC
	}
	x.mu.Lock()
	defer x.mu.Unlock()
	if x.session == nil {
		return ErrRPC
	}
	return x.session.Ping(id)
}

func (x *Client) Call(ctx context.Context, request tl.Dynamic) (tl.Dynamic, error) {
	if x == nil {
		return tl.Dynamic{}, ErrRPC
	}
	x.mu.Lock()
	defer x.mu.Unlock()
	if x.session == nil || x.schema == nil {
		return tl.Dynamic{}, ErrRPC
	}
	if !x.initialized {
		if err := x.initialize(ctx); err != nil {
			return tl.Dynamic{}, err
		}
	}
	return x.callRaw(ctx, request)
}

func (x *Client) initialize(ctx context.Context) error {
	if x.apiID <= 0 || x.apiID > math.MaxInt32 {
		return ErrRPC
	}
	device := x.deviceModel
	if device == "" {
		device = "GTG"
	}
	system := x.systemVersion
	if system == "" {
		system = "Go"
	}
	version := x.appVersion
	if version == "" {
		version = "0.2"
	}
	language := x.language
	if language == "" {
		language = "en"
	}
	query := tlgen.NewMethodHelpGetConfig_C4F9186B().Request()
	connection := tlgen.MethodInitConnection_C1CD5EA9{
		FFlags1:          0,
		FApiId2:          int32(x.apiID),
		FDeviceModel3:    device,
		FSystemVersion4:  system,
		FAppVersion5:     version,
		FSystemLangCode6: language,
		FLangPack7:       "",
		FLangCode8:       language,
		FQuery11:         query,
	}.Request()
	wrapped := tlgen.MethodInvokeWithLayer_DA9B0D0D{FLayer1: int32(tlgen.Layer), FQuery2: connection}.Request()
	_, err := x.callRaw(ctx, wrapped)
	if err == nil {
		x.initialized = true
	}
	return err
}

func (x *Client) AuthorizeBot(ctx context.Context, token []byte) (tl.Dynamic, error) {
	if x == nil || len(token) == 0 {
		return tl.Dynamic{}, ErrRPC
	}
	x.mu.Lock()
	defer x.mu.Unlock()
	if x.session == nil || x.schema == nil || len(x.apiHash) == 0 {
		return tl.Dynamic{}, ErrRPC
	}
	if !x.initialized {
		if err := x.initialize(ctx); err != nil {
			return tl.Dynamic{}, err
		}
	}
	if x.apiID <= 0 || x.apiID > math.MaxInt32 {
		return tl.Dynamic{}, ErrRPC
	}
	request := tlgen.MethodAuthImportBotAuthorization_67A3FF2C{
		FFlags1:        0,
		FApiId2:        int32(x.apiID),
		FApiHash3:      string(x.apiHash),
		FBotAuthToken4: string(token),
	}.Request()
	result, err := x.callRaw(ctx, request)
	clear(x.apiHash)
	x.apiHash = nil
	return result, err
}

func (x *Client) GetMe(ctx context.Context) (tl.Dynamic, error) {
	self := tlgen.NewConstructorInputUserSelf_F7C1B13F().Dynamic()
	return x.Call(ctx, tlgen.MethodUsersGetFullUser_B60F5918{FId1: self}.Request())
}

func (x *Client) callRaw(ctx context.Context, request tl.Dynamic) (tl.Dynamic, error) {
	encoded, err := x.schema.Encode(request)
	if err != nil {
		return tl.Dynamic{}, err
	}
	requestID, messages, err := x.session.Exchange(ctx, encoded)
	if err != nil {
		return tl.Dynamic{}, err
	}
	defer clearMessages(messages)
	for _, message := range messages {
		response, matched, err := x.decodeRPCResult(message, requestID)
		if err != nil {
			return tl.Dynamic{}, err
		}
		if matched {
			return response, nil
		}
	}
	return tl.Dynamic{}, ErrRPC
}

func (x *Client) decodeRPCResult(message []byte, requestID uint64) (tl.Dynamic, bool, error) {
	result, ok := x.schema.Declaration("rpc_result")
	if !ok || len(message) < 12 || binaryLittle(message[:4]) != result.Constructor {
		return tl.Dynamic{}, false, nil
	}
	if binaryLittle64(message[4:12]) != requestID {
		return tl.Dynamic{}, false, nil
	}
	return x.decodeResult(message[12:])
}

func (x *Client) decodeResult(data []byte) (tl.Dynamic, bool, error) {
	gzipPacked, hasGzip := x.schema.Declaration("gzip_packed")
	if hasGzip && len(data) >= 4 && binaryLittle(data[:4]) == gzipPacked.Constructor {
		packed, err := tlBytes(data[4:])
		if err != nil {
			return tl.Dynamic{}, true, ErrRPC
		}
		plain, err := unpackGzip(packed)
		clear(packed)
		if err != nil {
			return tl.Dynamic{}, true, ErrRPC
		}
		defer clear(plain)
		return x.decodeResult(plain)
	}
	value, unknown, err := x.schema.Decode(data)
	if err != nil || unknown != nil {
		return tl.Dynamic{}, true, ErrRPC
	}
	if value.Name == "rpc_error" {
		code, ok := value.Fields["error_code"].(int32)
		if !ok {
			return tl.Dynamic{}, true, ErrRPC
		}
		message, ok := value.Fields["error_message"].(string)
		if !ok {
			return tl.Dynamic{}, true, ErrRPC
		}
		return tl.Dynamic{}, true, parseRPCError(int(code), message)
	}
	return value, true, nil
}

func parseRPCError(code int, message string) error {
	result := &RPCError{Code: code, Message: message}
	for _, prefix := range []string{"FLOOD_WAIT_", "SLOWMODE_WAIT_"} {
		if strings.HasPrefix(message, prefix) {
			result.FloodWait, _ = strconv.Atoi(strings.TrimPrefix(message, prefix))
			return result
		}
	}
	for _, prefix := range []string{"PHONE_MIGRATE_", "NETWORK_MIGRATE_", "USER_MIGRATE_", "FILE_MIGRATE_"} {
		if strings.HasPrefix(message, prefix) {
			result.MigrateDC, _ = strconv.Atoi(strings.TrimPrefix(message, prefix))
			return result
		}
	}
	return result
}

func unpackGzip(data []byte) ([]byte, error) {
	reader, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer reader.Close()
	return io.ReadAll(io.LimitReader(reader, 16<<20))
}

func tlBytes(data []byte) ([]byte, error) {
	if len(data) < 1 {
		return nil, ErrRPC
	}
	length := int(data[0])
	header := 1
	position := 1
	if length == 254 {
		if len(data) < 4 {
			return nil, ErrRPC
		}
		length = int(data[1]) | int(data[2])<<8 | int(data[3])<<16
		header = 4
		position = 4
	} else if length == 255 {
		return nil, ErrRPC
	}
	padding := (4 - (length+header)&3) & 3
	if length < 0 || len(data) != header+length+padding {
		return nil, ErrRPC
	}
	for _, value := range data[position+length:] {
		if value != 0 {
			return nil, ErrRPC
		}
	}
	return append([]byte(nil), data[position:position+length]...), nil
}

func binaryLittle(data []byte) uint32 {
	return uint32(data[0]) | uint32(data[1])<<8 | uint32(data[2])<<16 | uint32(data[3])<<24
}

func binaryLittle64(data []byte) uint64 {
	return uint64(binaryLittle(data)) | uint64(binaryLittle(data[4:]))<<32
}

func clearMessages(messages [][]byte) {
	for _, message := range messages {
		clear(message)
	}
}
