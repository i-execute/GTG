# Vault cells

The `session` package calls its multi-account encrypted containers **Vault cells**. A cell is an independently authenticated record inside a versioned session store. The theme is deliberately small: a vault has named cells, one active cell, sealed records, and key rotation.

## Contents

An `Account` cell records account kind, test mode, selected DC, DC endpoints, authorization key and id, server salt, time offset, user id, API id, encrypted bot token when applicable, schema layer, peers, and update checkpoints. A store can hold multiple named cells and selects exactly one active cell.

## Protection model

The `GTS2` container has a versioned header. It records Argon2id parameters and a fresh file salt. Every cell, including the active-cell metadata record, has an independent random salt and AES-256-GCM nonce. Header data, record name, account kind, record salt, and nonce are authenticated additional data. Per-record keys are derived from the root key with HKDF-SHA-256.

Password credentials use Argon2id. Raw 32-byte credentials support environment-only key injection. Machine-bound credentials apply HKDF to the raw key and caller-provided machine material; callers decide how that material is obtained and must not treat a mutable hostname as an authentication factor.

All malformed, altered, truncated, wrong-key, and unexpected-version container inputs return the single authentication error. `Account.Destroy`, `Credential.Destroy`, and `Store.Destroy` clear owned sensitive byte slices before release.

## File lifecycle

`SaveFile` creates parent directories with private permissions, takes a lock, writes a mode-0600 temporary file, syncs it, atomically renames it, then attempts to sync the directory. `LoadFile` and `RotateFile` use the same lock. Windows uses an exclusive lock-file fallback so all supported target builds remain pure Go and cgo-free.

## Transfer and compatibility

`EncodePortable` and `DecodePortable` use the `gtgs2:` base64url transfer format. `ImportTelethon` and `ExportTelethon` translate the public StringSession layout. `ParsePyrogram` and `Account.PyrogramString` translate the public session-string layout. Imported data remains a cell until explicitly written into a sealed store.

## Operations

```go
credential, _ := session.NewPasswordCredential(password, session.DefaultKDF())
store := session.NewStore()
_ = store.Put("bot", account)
_ = store.Activate("bot")
_ = session.SaveFile(path, store, credential)
restored, _ := session.LoadFile(path, credential)
_ = session.RotateFile(path, credential, replacement)
```

Credentials, accounts, stores, and decoded portable bytes must be destroyed by callers after use.
