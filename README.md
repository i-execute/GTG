# GTG

GTG is a pure-Go MIT-licensed foundation for Telegram MTProto work. The module path is `github.com/i-execute/GTG`. It has no cgo dependency.

## Status

GTG is a foundation and is not production-ready. It provides tested low-level cryptographic and transport primitives, a locked TL schema with dynamic and generated typed surfaces, local encrypted storage, a bounded RPC lifecycle policy, update checkpoint mechanics, entity caching, and restricted high-level helpers.

The completed pieces are deliberately narrower than a complete client. See [docs/STATE.md](docs/STATE.md) and [docs/limitations.md](docs/limitations.md) before relying on any package.

## Build and test

Use Go 1.27.4 or the version declared by `go.mod`.

```text
gofmt -w .
go test -p 1 ./... -count=1
go vet -p 1 ./...
go test -p 1 -race ./... -count=1
go vet -asmdecl ./core
```

`-p 1` is suitable for constrained builders with the generated TL surface. It changes only package-build parallelism.

## Schema layer

The lock in `schema/telegram.lock.json` pins the exact TDLib commit, protocol layer, and SHA-256 digests of the Telegram API and MTProto schemas. Generation verifies digests and rejects mismatches.

Fetch the current TDLib schema, update the lock, and regenerate deterministically:

```text
go run ./cmd/tlgen -layer latest
```

Or pin a specific TDLib commit:

```text
go run ./cmd/tlgen -layer <40-character-commit>
```

Offline generation from local schema inputs remains available:

```text
scripts/update-schema.sh <revision> <layer> <telegram-schema> <mtproto-schema>
go run ./cmd/tlgen -input telegram_api.tl,mtproto_api.tl
```

Run the test suite after regeneration. The public typed facade is in `telegram`; the dynamic codec is in `tl`. The scheduled GitHub workflow (`.github/workflows/schema-update.yml`) performs the same update and opens a pull request when the locked schema changes, using only the default `GITHUB_TOKEN`.

## Telethon StringSession compatibility

`session.ParseTelethon` parses a Telethon StringSession (IPv4 and IPv6 forms), `Telethon.String` exports one, and `session.StoreTelethon`/`LoadTelethon` persist it in the encrypted vault. `auth` builds user-session storage on top of it. See [docs/authorization.md](docs/authorization.md).

## Scope limits

Do not treat GTG as a complete Telegram client. Full session negotiation, autonomous receive/reconnect workers, authorization transfer, broad peer resolution, media flows, callback flows, and live end-to-end client interoperability remain outside the verified scope.

## Documentation

- [Project state](docs/STATE.md)
- [Architecture](docs/architecture.md)
- [Schema and codec](docs/schema.md)
- [Transport and lifecycle](docs/transport.md)
- [Updates](docs/updates.md)
- [Entities](docs/entities.md)
- [Authorization](docs/authorization.md)
- [High-level API](docs/api.md)
- [Limitations](docs/limitations.md)
