# Project state

## Next client-layer program

- Active branch: `next`, based on public `v0.1.0` at `545d0b7f8b1ad0e5ccbc28e9f3d12208e833ba13`.
- Scope: advance the pure-Go library toward a verified client layer while preserving `main` and tags unchanged. Work is checkpointed on `next` only.
- Author and committer policy: `i-execute <i_execute@icloud.com>`.
- Current execution host: Linux amd64, Intel Xeon Processor at 2.60 GHz, two visible logical CPUs, KVM virtualization, Go 1.27.4 and Python 3.13.18. This is not the requested Windows Ryzen target. Measurements from this host are recorded as Linux/KVM-only and are not Windows or Zen 4 claims.
- Secrets are environment-only. No credential, chat identity, local path, or secret-derived output belongs in this repository, docs, commits, evidence, or test logs.

## Baseline present before next work

- Pure-Go AES-IGE, GCM wrappers, SHA state, MTProto message-key and packet helpers, key bootstrap components, TL codec and a bounded RPC foundation exist.
- A general encrypted vault exists, but it is not yet a full multi-account client session store with record migration, account activation, atomic file lifecycle, or live restore coverage.
- The schema is pinned and generated, but the generator, dynamic coverage, client transport lifecycle, and live session path must be audited against the next-program requirements.
- The public branch does not claim a production-complete Telegram client. `next` must retain that honesty until live checks prove a bounded path.

## Completed on next

- Baseline unit, vet, assembly-declaration, and race validation passed with `GOGC=20` after constraining compilation memory. The host limitation and its KVM/Intel boundary are recorded above.
- Added the Vault-cell session store in `session`: multiple named accounts, active-cell selection, account/update/peer metadata, AES-256-GCM sealed records, Argon2id password credentials, raw and machine-bound credentials, HKDF record keys, rotation, portable transfer, atomic file replacement, lock-file concurrency fallback, public session-string import/export, tamper tests, fuzz input, race checks, and Linux/Windows cross-compilation checks.
- Added `client.ConfigFromAccount` so a restored Vault cell can construct an encrypted client configuration without exposing a caller-side reconstruction path.
- Corrected `EncryptedSession.Exchange` to retain service frames until the matching `rpc_result` arrives. The previous first-frame return could discard a valid later RPC response after an acknowledgement or other service frame.
- Completed a controlled live bot run without persisting credentials. Bootstrap, encrypted ping, initialization, bot authorization, typed and dynamic config calls, get-me, session marshal/open, restored session use without a second bot login, and a send/edit/delete cycle in the supplied chat passed. `docs/LIVE.md` contains only non-secret results.
- Split vault OS-dependent memory locking and file-lock behavior behind allowed build tags so session and vault paths cross-compile for Linux and Windows targets without cgo.
- Ran `FuzzStoreOpen` for a bounded 30-second single-worker campaign under `GOGC=20`. It completed without a crash, failure, or persisted corpus addition; it is bounded malformed-input evidence, not an exhaustive security proof.

## Current work order

1. Add bounded MTProto Seal/Open benchmark coverage and analyze only retained A/B/A/B results on the actual target host.
2. Audit schema regeneration and extend transport lifecycle, update handling, and recovery paths with protocol-level tests.
3. Extend GTG-bench timer calibration, operation matrix, system reporting, and keyboard interaction independently of GTG source.
4. Run fuzz, full-package cross-build, scans, and release packaging after each additional checkpoint.
5. Keep benchmark work in GTG-bench only; do not add external-comparison material to GTG.

## Required verification before any delivery

```text
go test -p 1 ./... -count=1
go vet -p 1 ./...
go vet -asmdecl ./core
GOGC=20 go test -p 1 -race ./... -count=1
```

Additional fuzz, cross-build, static scans, and live checks are tracked as work is added.
