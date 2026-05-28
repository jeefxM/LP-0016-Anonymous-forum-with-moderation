#!/usr/bin/env bash
# Smoke test for the proof-daemon against a live LEZ chain (Hetzner).
# Exercises every endpoint category: pure-crypto, chain, and proving.
#
# Prereqs: the daemon is running (see top of src/main.rs for env), `jq` and
# `curl` installed, and the `seq` + `bedrock` chain sessions are up.
#
#   B=http://127.0.0.1:8787 ./smoke.sh
set -euo pipefail

B="${B:-http://127.0.0.1:8787}"
FORUM="smoke-$(date +%s)"
ZHASH=$(printf '0%.0s' $(seq 1 64))            # 32 zero bytes, hex
PATH16=$(jq -nc --arg z "$ZHASH" '[range(16) | $z]')
CID=$(printf 'aa%.0s' $(seq 1 32))             # content id

# Pipe the body via stdin (printf is a shell builtin, so it isn't bound by
# ARG_MAX) — real-mode receipts are multi-MB and overflow a curl `-d` arg.
post() { printf '%s' "$2" | curl -sS -X POST "$B$1" -H 'content-type: application/json' --data-binary @-; }

echo "== health"
curl -sS "$B/v1/health"; echo

echo "== identity/create"
ID=$(post /v1/identity/create '{}'); echo "$ID"
SECRET=$(jq -r .secret <<<"$ID")
COMMIT=$(jq -r .commitment <<<"$ID")

echo "== bootstrap 3 moderator pubkeys (via sign_vote)"
mpub() {
  post /v1/moderation/sign "{\"moderatorSecret\":\"$1\",\"contentId\":\"$ZHASH\",\"strikeIndex\":0,\"shareX\":\"$ZHASH\",\"shareY\":\"$ZHASH\"}" | jq -r .moderator
}
M1S=$(printf '01%.0s' $(seq 1 32)); M2S=$(printf '02%.0s' $(seq 1 32)); M3S=$(printf '03%.0s' $(seq 1 32))
M1=$(mpub "$M1S"); M2=$(mpub "$M2S"); M3=$(mpub "$M3S")
echo "moderators: $M1 $M2 $M3"

echo "== forum/create ($FORUM)"
post /v1/forum/create "{\"forumId\":\"$FORUM\",\"moderators\":[\"$M1\",\"$M2\",\"$M3\"],\"nThreshold\":2,\"kThreshold\":3,\"stakeAmount\":\"1000\"}"; echo

echo "== forum/load"
post /v1/forum/load "{\"forumId\":\"$FORUM\"}"; echo

echo "== member/register (leaf 0, empty path)"
post /v1/member/register "{\"forumId\":\"$FORUM\",\"commitment\":\"$COMMIT\",\"pathBefore\":$PATH16,\"leafIndex\":0}"; echo

echo "== forum/load (root should have advanced)"
LOADED=$(post /v1/forum/load "{\"forumId\":\"$FORUM\"}"); echo "$LOADED"
ROOT=$(jq -r .treeRoot <<<"$LOADED")

echo "== member/is-revoked (expect false)"
post /v1/member/is-revoked "{\"forumId\":\"$FORUM\",\"commitment\":\"$COMMIT\"}"; echo

echo "== post/prove (RISC0_DEV_MODE speeds this up)"
ENV=$(post /v1/post/prove "{\"secret\":\"$SECRET\",\"treeRoot\":\"$ROOT\",\"merkleSiblings\":$PATH16,\"pathBits\":0,\"contentId\":\"$CID\",\"epoch\":1,\"kThreshold\":3}")
echo "$ENV" | jq 'del(.receipt)'
SX=$(jq -r .shareX <<<"$ENV"); SY=$(jq -r .shareY <<<"$ENV")

echo "== post/verify (expect valid:true)"
post /v1/post/verify "{\"forumId\":\"$FORUM\",\"envelope\":$ENV}"; echo

echo "== moderation/sign x2 over the post's share"
V1=$(post /v1/moderation/sign "{\"moderatorSecret\":\"$M1S\",\"contentId\":\"$CID\",\"strikeIndex\":0,\"shareX\":\"$SX\",\"shareY\":\"$SY\"}")
V2=$(post /v1/moderation/sign "{\"moderatorSecret\":\"$M2S\",\"contentId\":\"$CID\",\"strikeIndex\":0,\"shareX\":\"$SX\",\"shareY\":\"$SY\"}")

echo "== moderation/aggregate (2-of-3, expect cert)"
CERT=$(post /v1/moderation/aggregate "{\"nThreshold\":2,\"votes\":[$V1,$V2]}")
echo "$CERT"

echo "== slash/reconstruct with 1 cert (expect null — below K=3)"
post /v1/slash/reconstruct "{\"forumId\":\"$FORUM\",\"certificates\":[$CERT],\"leafIndex\":0,\"merklePath\":$PATH16}"; echo

echo "== SMOKE OK"
