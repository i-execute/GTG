# Migration notes for next

The `next` branch adds Vault-cell session storage and `client.ConfigFromAccount`. Existing public `session.Telethon`, `ParseTelethon`, `StoreTelethon`, and `LoadTelethon` names remain available without behavioral removal. They are compatibility helpers for a single imported session; new code should prefer `session.Account`, `session.Store`, `SaveFile`, and `LoadFile` when it needs multiple accounts, active-cell selection, record authentication, rotation, and update state.

The public MTProto aliases remain stable. `EncryptedSession.Exchange` now retains non-result service messages until it receives the matching `rpc_result`, or reports its bounded failure. This is a behavior correction, not an API rename.

The `next` branch is not a tagged production release. Applications must not move to it without their own validation and migration review.
