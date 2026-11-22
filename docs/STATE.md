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

## Current work order

1. Establish full baseline validation and inspect existing crypto, bootstrap, session, schema, and client paths.
2. Add bounded MTProto packet and session-store correctness work with differential, tamper, race, fuzz, and allocation tests.
3. Audit schema regeneration and client lifecycle, then add a live test runner that skips cleanly without environment credentials and never persists them.
4. Evaluate crypto changes only with retained A/B/A/B raw output. Reject candidates that lack a significant benefit.
5. Keep benchmark work in GTG-bench only; do not add external-comparison material to GTG.

## Required verification before any delivery

```text
go test -p 1 ./... -count=1
go vet -p 1 ./...
go vet -asmdecl ./core
GOGC=20 go test -p 1 -race ./... -count=1
```

Additional fuzz, cross-build, static scans, and live checks are tracked as work is added.
