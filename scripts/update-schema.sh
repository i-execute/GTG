#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -ne 4 ]; then
  printf '%s\n' "usage: $0 <revision> <layer> <telegram-schema> <mtproto-schema>" >&2
  exit 2
fi

revision=$1
layer=$2
first=$3
second=$4
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$root"

if [[ ! "$revision" =~ ^[0-9a-fA-F]{40}$ ]]; then
  printf '%s\n' "revision must be a 40-character hexadecimal identifier" >&2
  exit 2
fi

case "$layer" in
  *[!0-9]*|'')
    printf '%s\n' "layer must be a positive integer" >&2
    exit 2
    ;;
esac

if [ ! -f "$first" ] || [ ! -f "$second" ]; then
  printf '%s\n' "schema inputs must be readable files" >&2
  exit 2
fi

first_digest=$(sha256sum "$first" | awk '{print $1}')
second_digest=$(sha256sum "$second" | awk '{print $1}')
python3 - "$revision" "$layer" "$first_digest" "$second_digest" <<'PY'
import json
import sys
with open("schema/telegram.lock.json", "w", encoding="utf-8") as handle:
    json.dump({"schema_revision": sys.argv[1], "layer": int(sys.argv[2]), "schemas": [{"name": "telegram_api", "source": "https://raw.githubusercontent.com/tdlib/td/" + sys.argv[1] + "/td/generate/scheme/telegram_api.tl", "sha256": sys.argv[3]}, {"name": "mtproto_api", "source": "https://raw.githubusercontent.com/tdlib/td/" + sys.argv[1] + "/td/generate/scheme/mtproto_api.tl", "sha256": sys.argv[4]}]}, handle, indent=2)
    handle.write("\n")
PY
go run ./cmd/tlgen -input "$first,$second" -out internal/tlgen/registry_generated.go -types-out internal/tlgen/types_generated.go -public-out telegram/types_generated.go
gofmt -w internal/tlgen telegram
go test -p 1 ./tl ./internal/tlparse ./internal/tlgen ./telegram ./cmd/tlgen
