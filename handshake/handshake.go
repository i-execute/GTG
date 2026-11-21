package handshake

import core "github.com/i-execute/GTG/core"

type RSAPublicKey = core.RSAPublicKey
type TemporaryAES = core.TemporaryAES

var Err = core.ErrHandshake
var FactorPQ = core.FactorPQ
var FactorPQBytes = core.FactorPQBytes
var RSAFingerprint = core.RSAFingerprint
var RSAEncryptPad = core.RSAEncryptPad
var DeriveTemporaryAES = core.DeriveHandshakeTemporaryAES
var ServerSalt = core.ServerSalt
var EncryptDHAnswer = core.EncryptDHAnswer
var DecryptDHAnswer = core.DecryptDHAnswer
var GenerateDHSecret = core.GenerateDHSecret
var ComputeDHAuthKey = core.ComputeDHAuthKey
var ValidateDH = core.ValidateTelegramDH
var ValidatePublic = core.ValidateDHPublic
var NewNonceHash = core.NewNonceHash
