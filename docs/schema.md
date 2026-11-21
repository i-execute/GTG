# Schema and codec

The checked-in schema lock pins an exact TDLib source commit, its TDLib-derived protocol layer, and SHA-256 digests for both the Telegram API and MTProto schemas. Generation verifies every input against the lock digests and rejects mismatches.

`cmd/tlgen -layer latest` resolves the current `tdlib/td` HEAD commit (or `-layer <commit>` pins one), downloads both schemas from the official TDLib repository, reads `td/telegram/Version.h` for the layer, updates the lock, and regenerates deterministically. Offline generation from local schema inputs remains available via `cmd/tlgen -input …` and `scripts/update-schema.sh`.

The scheduled GitHub workflow runs the update and opens a proposed schema-update pull request whenever the locked schema changes, using only the default `GITHUB_TOKEN`.

`tl` provides dynamic values with explicit decode limits. `internal/tlgen` stores the generated declaration registry and generated typed constructors. `telegram` exposes the public typed facade.
