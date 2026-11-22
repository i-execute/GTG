# Live verification

## Controlled bot run

A controlled live run was completed on the `next` branch with environment-provided credentials. No credential values, account identifiers, chat identifiers, authorization keys, salts, or message identifiers were written to this document.

| Check | Result |
|---|---|
| Plain authorization-key bootstrap | Passed |
| Encrypted MTProto ping/pong | Passed |
| `invokeWithLayer` and `initConnection` | Passed |
| `auth.importBotAuthorization` | Passed |
| Typed `help.getConfig` | Passed |
| Dynamic `help.getConfig` | Passed |
| `users.getFullUser` through `GetMe` | Passed |
| Session-store marshal/open and second encrypted connection without another bot login | Passed |
| `messages.sendMessage` in the supplied chat | Passed |
| `messages.editMessage` for the test message | Passed |
| `messages.deleteMessages` for the test message | Passed |

The test made one send, one edit, and one delete request in the supplied chat. The message text contained only a fixed verification marker. No other chat was targeted. The live message-history cleanup helper was not relied upon for the successful path because the direct delete request returned successfully.

## Environment boundary

The live run executed on Linux amd64 in a KVM guest with two visible logical CPUs and an Intel Xeon Processor at 2.60 GHz. It validates the bounded client path above on that environment only. It is not a Windows, Ryzen, arm64, throughput, or production-readiness claim.

## Invocation

```text
GTG_LIVE=1 GTG_LIVE_MESSAGES=1 go test -tags=integration -p 1 ./client -run '^TestLiveBotSession$' -count=1
```

The test skips cleanly if the required environment values are absent. It never reads credentials from files, source, CI configuration, or a fallback account.
