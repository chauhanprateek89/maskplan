#!/bin/sh
# Loads the synthetic bank, then the support bot's access mistakes.
set -eu
fintech-load -dsn "$MASKPLAN_DSN" -schema-sql /demo/schema.sql -customers 2000
psql "$MASKPLAN_DSN" -v ON_ERROR_STOP=1 -q -f /demo/misconfig.sql
echo "Loaded the bank (schema fintech, 2,000 customers) and the role support_bot."
