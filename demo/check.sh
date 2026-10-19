#!/bin/sh
# Runs the whole demo and checks what it shows, as CI does: the demo must
# work the first time a stranger runs it. Pass extra compose flags in
# COMPOSE_FLAGS. Leaves the database running; `docker compose down -v` ends it.
set -eu
cd "$(dirname "$0")"
dc() { docker compose ${COMPOSE_FLAGS:-} "$@"; }
run() { dc run --rm -T "$@" 2>/dev/null; }
fail() { echo "demo check failed: $*" >&2; exit 1; }

dc down -v >/dev/null 2>&1 || true
rm -f work/classification.yaml work/maskplan.yaml
dc up -d --wait db >/dev/null
run --entrypoint /demo/load.sh maskplan >/dev/null
run maskplan scan --schema fintech >/dev/null

# The support bot's five mistakes, each found.
set +e
out=$(run maskplan report --role support_bot)
code=$?
set -e
[ "$code" = 1 ] || fail "report on support_bot exited $code, want 1"
for want in \
  "RAW       fintech.support_tickets.callback" \
  "inherited: support_bot > analytics_readers" \
  "RAW       reporting.customer_contacts.mobile" \
  "UNKNOWN   reporting.customer_contacts.email_hash" \
  "UNKNOWN   function reporting.customer_email(bigint)" \
  "WARN      default privileges in schema fintech"; do
  echo "$out" | grep -qF "$want" || fail "report on support_bot lacks: $want"
done

# A clean agent: apply builds it and checks it.
run maskplan init >/dev/null
run maskplan plan >/dev/null
run maskplan apply --yes | grep -qF "PASS: no raw personal data" || fail "apply's own report did not pass"
run maskplan report --role ai_agent --policy maskplan.yaml >/dev/null || fail "report on ai_agent failed"

# The agent reads tokens, and cannot read the bank's tables.
row=$(run --entrypoint psql maskplan -Atc "SELECT email FROM customers LIMIT 1" "postgres://ai_agent:demo-only-password@db:5432/bank?sslmode=disable")
case "$row" in tok_*) ;; *) fail "the agent read $row, want a token" ;; esac
if run --entrypoint psql maskplan -Atc "SELECT email FROM fintech.customers LIMIT 1" "postgres://ai_agent:demo-only-password@db:5432/bank?sslmode=disable" >/dev/null; then
  fail "the agent can read fintech.customers"
fi
echo "demo check passed"
