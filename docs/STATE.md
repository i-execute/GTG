# Project state

## History repair (this commit)

- Commit author and committer identity was wrong in the previous public history. All commits were rewritten to `i-execute <i_execute@icloud.com>`; dates, messages, and file trees are unchanged, so only commit hashes differ. Old refs, reflogs, and unreachable objects were pruned. Branch: `main`; no tags.
- Session-compatibility and schema-source naming was restored after the privacy cleanup over-generalized it: the Telethon StringSession type and helpers use their honest names (`session.Telethon`, `ParseTelethon`, `StoreTelethon`, `LoadTelethon`; files `session/telethon.go`), and the schema lock names the official TDLib source URLs and commit instead of `maintainer-supplied` labels. TDLib and Telethon are open-source projects; the naming restriction only ever applied to the removed comparison target, which stays excluded.
- `cmd/tlgen -layer latest|<commit>` restores online schema updates: it resolves the current `tdlib/td` HEAD, downloads both schemas, reads the layer from `td/telegram/Version.h`, verifies digests, updates the lock, and regenerates deterministically. Offline generation from local files remains available. `.github/workflows/schema-update.yml` runs the update weekly (and on demand), tests, and opens a PR with the schema diff using only the default `GITHUB_TOKEN`; no secrets are stored in the repository.

## Completed

- Pure-Go cryptographic primitives, MTProto packet helpers, authorization-key bootstrap building blocks, obfuscation helpers, and encrypted vault storage.
- Locked TL schema parsing, deterministic registry generation, dynamic codec, bounded owned and borrowed decoding, and public generated typed aliases.
- Serialized dynamic RPC client foundation with bounded retry, flood-wait, and caller-supplied migration configuration.
- Update checkpoints, standard update envelope expansion, difference request construction, entity cache ingestion, validated input-peer construction, and restricted high-level messaging helpers.
- Unit, race, vet, and assembly-declaration validation are part of the current checked-in verification path. Fuzz targets and cross-build coverage are present but require separate execution on suitable builders.

## Not completed

GTG is not production-ready and is not a complete Telegram client. Full MTProto session negotiation, authorization transfer, autonomous receive/reconnect loops, live update polling, broad resolution, media, callbacks, and native arm64 runtime validation remain outside the verified scope.

## Next steps

1. Validate the bounded client path against a controlled live environment without logging credentials.
2. Add explicit session and authorization-transfer mechanics before automatic migration is considered complete.
3. Add durable update replay and channel-specific recovery only with protocol-level tests.
4. Regenerate and review the schema lock when updating the protocol layer.

## Local verification

```text
go test -p 1 ./... -count=1
go vet -p 1 ./...
go test -p 1 -race ./... -count=1
go vet -asmdecl ./core
```

## Conventions

- Keep the module path `github.com/i-execute/GTG`.
- Keep production Go and assembly free of comments except required build constraints.
- Never put credentials, tokens, private keys, or local paths in source, logs, commits, or generated artifacts.
- Keep the implementation pure Go without cgo.
- Keep measurements reproducible from checked-in benchmark sources; do not turn local measurements into interoperability claims without a documented compatible protocol.
- At the start of a future session, unpack the project archive, read this file and `git log`, then continue from the current `main` history. At the end, update this file, commit it, and produce a new archive.
