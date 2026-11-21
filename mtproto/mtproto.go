package mtproto

import core "github.com/i-execute/GTG/core"

type Direction = core.Direction
type MTProto = core.MTProto
type MTProtoPool = core.MTProtoPool
type MTProtoSealStream = core.MTProtoSealStream
type MTProtoOpenStream = core.MTProtoOpenStream
type MTProtoPacketStream = core.MTProtoPacketStream

const (
	ClientToServer = core.ClientToServer
	ServerToClient = core.ServerToClient
)

var ErrPadding = core.ErrMTProtoPadding
var ErrDestination = core.ErrMTProtoDestination
var ErrMessageKey = core.ErrMTProtoMessageKey
var ErrPacket = core.ErrMTProtoPacket

var New = core.NewMTProto
var NewPool = core.NewMTProtoPool
var MessageKey = core.MessageKey
var DeriveAES = core.DeriveMessageAES
