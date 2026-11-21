package obfuscation

import core "github.com/i-execute/GTG/core"

type Stream = core.Obfuscation
type ProxySecretKind = core.ProxySecretKind

const (
	Plain = core.ProxySecretPlain
	DD    = core.ProxySecretDD
	EE    = core.ProxySecretEE
)

var Err = core.ErrObfuscation
var ParseSecret = core.ParseProxySecret
var FakeTLSDomain = core.FakeTLSDomain
var NewClient = core.NewObfuscatedInit
var NewServer = core.NewObfuscationFromInit
var FakeTLSClientDigest = core.FakeTLSClientDigest
var VerifyFakeTLSClientDigest = core.VerifyFakeTLSClientDigest
var FakeTLSServerDigest = core.FakeTLSServerDigest
var VerifyFakeTLSServerDigest = core.VerifyFakeTLSServerDigest
