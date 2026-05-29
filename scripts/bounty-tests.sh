#!/usr/bin/env bash
# Human-readable view of the seven LP-0016 bounty-required tests. Runs the
# host-side Rust suite and maps each named test to a plain-English result.
# Exits non-zero if any required test is missing or failing.
set -uo pipefail
cd "$(dirname "$0")/.."

if [ -t 1 ]; then G=$'\033[32m'; R=$'\033[31m'; B=$'\033[1m'; X=$'\033[0m'; else G=; R=; B=; X=; fi

echo "Running the LP-0016 bounty-required tests (host-side suite)..."
OUT="$(cargo test --workspace --exclude proof-host 2>&1)"

# test name | plain-English description (the order the bounty lists them)
TESTS=(
	"valid_registration|a member registers and the membership tree advances"
	"valid_post_proof|an anonymous post carries a valid membership proof"
	"moderation_cert_construction|N-of-M moderators build a moderation certificate"
	"moderation_cert_verification|a certificate verifies; tampered/short ones are rejected"
	"strike_accumulation|K strikes accumulate against the same member"
	"slash_submission|the accumulated evidence yields a valid slash"
	"post_rejection_after_revocation|a revoked member's later posts are rejected"
)

echo
echo "${B}LP-0016 bounty-required tests${X}"
echo "------------------------------------------------------------------------"
pass=0
total=0
for entry in "${TESTS[@]}"; do
	name="${entry%%|*}"
	desc="${entry#*|}"
	total=$((total + 1))
	if grep -qE "::${name} \.\.\. ok" <<<"$OUT"; then
		printf "  ${G}PASS${X}  %-34s %s\n" "$name" "$desc"
		pass=$((pass + 1))
	else
		printf "  ${R}FAIL${X}  %-34s %s\n" "$name" "$desc"
	fi
done
echo "------------------------------------------------------------------------"
if [ "$pass" -eq "$total" ]; then
	echo "  ${G}${B}${pass}/${total} bounty-required tests passed${X}"
else
	echo "  ${R}${B}${pass}/${total} passed; see failures above${X}"
fi
echo
grep -E "test result:" <<<"$OUT" | sed 's/^/  cargo: /'

[ "$pass" -eq "$total" ]
