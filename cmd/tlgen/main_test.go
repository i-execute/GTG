package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/i-execute/GTG/tl"
)

func TestGenerateDeterministically(t *testing.T) {
	directory := t.TempDir()
	firstSource := []byte("vector#1cb5c415 {t:Type} # [ t ] = Vector t;\nnode#01020304 value:int = Node;\n---functions---\ncall#05060708 id:long = Node;\n")
	secondSource := []byte("pong#347773c5 msg_id:long ping_id:long = Pong;\n")
	firstDigest := sha256.Sum256(firstSource)
	secondDigest := sha256.Sum256(secondSource)
	firstInput := filepath.Join(directory, "first.tl")
	secondInput := filepath.Join(directory, "second.tl")
	lockPath := filepath.Join(directory, "lock.json")
	first := filepath.Join(directory, "first.go")
	second := filepath.Join(directory, "second.go")
	if err := os.WriteFile(firstInput, firstSource, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(secondInput, secondSource, 0o644); err != nil {
		t.Fatal(err)
	}
	lock := "{\"schema_revision\":\"0123456789012345678901234567890123456789\",\"layer\":1,\"schemas\":[{\"name\":\"first\",\"source\":\"https://example.invalid/first\",\"sha256\":\"" + hex.EncodeToString(firstDigest[:]) + "\"},{\"name\":\"second\",\"source\":\"https://example.invalid/second\",\"sha256\":\"" + hex.EncodeToString(secondDigest[:]) + "\"}]}"
	if err := os.WriteFile(lockPath, []byte(lock), 0o644); err != nil {
		t.Fatal(err)
	}
	input := firstInput + "," + secondInput
	if err := generate(lockPath, input, first, ""); err != nil {
		t.Fatal(err)
	}
	if err := generate(lockPath, input, second, ""); err != nil {
		t.Fatal(err)
	}
	left, err := os.ReadFile(first)
	if err != nil {
		t.Fatal(err)
	}
	right, err := os.ReadFile(second)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(left, right) {
		t.Fatal("non-deterministic output")
	}
	firstTypes, err := os.ReadFile(filepath.Join(directory, "first_types.go"))
	if err != nil {
		t.Fatal(err)
	}
	secondTypes, err := os.ReadFile(filepath.Join(directory, "second_types.go"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(firstTypes, secondTypes) || !bytes.Contains(firstTypes, []byte("type ConstructorNode_01020304 struct")) || !bytes.Contains(firstTypes, []byte("type MethodCall_05060708 struct")) {
		t.Fatal("non-deterministic typed output")
	}
	declarations := []tl.Declaration{{Name: "node", Constructor: 0x01020304, Result: "Node"}, {Name: "call", Constructor: 0x05060708, Result: "Node", Function: true}}
	firstPublic, err := renderPublicTypes(declarations)
	if err != nil {
		t.Fatal(err)
	}
	secondPublic, err := renderPublicTypes(declarations)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(firstPublic, secondPublic) || !bytes.Contains(firstPublic, []byte("type ConstructorNode_01020304 = internal.ConstructorNode_01020304")) || !bytes.Contains(firstPublic, []byte("func MethodCall_05060708FromDynamic")) {
		t.Fatal("non-deterministic public typed output")
	}
}

func TestGenerateRejectsModifiedInput(t *testing.T) {
	directory := t.TempDir()
	input := filepath.Join(directory, "schema.tl")
	lockPath := filepath.Join(directory, "lock.json")
	if err := os.WriteFile(input, []byte("node#01020304 value:int = Node;"), 0o644); err != nil {
		t.Fatal(err)
	}
	lock := "{\"schema_revision\":\"0123456789012345678901234567890123456789\",\"layer\":1,\"schemas\":[{\"name\":\"schema\",\"source\":\"https://example.invalid/schema\",\"sha256\":\"0000000000000000000000000000000000000000000000000000000000000000\"}]}"
	if err := os.WriteFile(lockPath, []byte(lock), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := generate(lockPath, input, filepath.Join(directory, "output.go"), ""); err == nil {
		t.Fatal("accepted modified input")
	}
}
