# Try maskplan in ten minutes

A synthetic Irish bank in Postgres, with a support bot whose access went wrong in five ordinary ways. You find them with `report`, then build a clean agent login with `apply`. Only Docker is needed, and nothing touches your own data: every row here is generated.

```bash
git clone https://github.com/chauhanprateek89/maskplan && cd maskplan/demo
docker compose build                    # a few minutes the first time
docker compose run --rm --entrypoint /demo/load.sh maskplan
```

The bank has 13 tables of customers, accounts, cards, transactions and tickets. [`misconfig.sql`](misconfig.sql) then sets up `support_bot`, which was meant to read ticket metadata only.

## 1. Find what the bot can really read

```bash
docker compose run --rm maskplan scan --schema fintech     # labels personal data: work/classification.yaml
docker compose run --rm maskplan report --role support_bot
```

```
RAW       fintech.support_tickets.callback           user.contact.phone                 SELECT on column granted to support_bot
RAW       fintech.transactions.counterparty_iban     user.financial.bank_account        SELECT granted to analytics_readers (inherited: support_bot > analytics_readers)
RAW       fintech.transactions.description           free_text                          SELECT granted to analytics_readers (inherited: support_bot > analytics_readers)
RAW       fintech.transactions.device_ip             user.device.ip_address             SELECT granted to analytics_readers (inherited: support_bot > analytics_readers)
RAW       fintech.transactions.terminal_id           user.contact.phone                 SELECT granted to analytics_readers (inherited: support_bot > analytics_readers)
RAW       reporting.customer_contacts.mobile         user.contact.phone                 passes through fintech.customers.mobile; view: SELECT granted to support_bot
UNKNOWN   function reporting.customer_email(bigint)  -                                  SECURITY DEFINER, runs as maskplan, who can read 39 labeled columns raw; executable by support_bot
UNKNOWN   reporting.customer_contacts.email_hash     user.contact.email                 expression over fintech.customers.email is not a maskplan transform: <expression hidden; ...>; view: SELECT granted to support_bot
WARN      default privileges in schema fintech       -                                  tables maskplan creates in schema fintech will be readable by analytics_readers, including any personal data added later

6 raw, 2 unknown, 1 warn. FAIL: raw personal data or key material is, or may be, reachable.
```

All five mistakes, each with the path that causes it:

- a column grant that also lists the callback number;
- membership of a dashboards role that reads transactions;
- a "masked" view that hashes emails without a key, which anyone can reverse by hashing guesses;
- a lookup function that runs with its owner's rights;
- default privileges that will expose every future table.

The classifier is not perfect, and this run shows it: `terminal_id` is labeled a phone number (it is an 8-digit terminal code), and `counterparty_name` is missed. That is why `classification.yaml` is meant to be reviewed.

## 2. Build a clean agent login

```bash
docker compose run --rm maskplan init                       # a starter policy: work/maskplan.yaml
docker compose run --rm maskplan plan                       # the SQL it would run; changes nothing
docker compose run --rm maskplan apply --yes                # builds it, then reports on it
```

apply ends with its own report on the new login, run the way an auditor would:

```
MASKED    ai_agent.customers.email                user.contact.email                 maskplan token of fintech.customers.email
MASKED    ai_agent.customers.first_name           user.name                          maskplan fake_name of fintech.customers.first_name
MASKED    ai_agent.customers.date_of_birth        user.demographic.date_of_birth     maskplan generalize_year of fintech.customers.date_of_birth
...
19 masked. PASS: no raw personal data or key material reachable.
```

Connect as the agent and look:

```bash
docker compose run --rm --entrypoint psql maskplan "postgres://ai_agent:demo-only-password@db:5432/bank?sslmode=disable" \
  -c "SELECT first_name, last_name, email, date_of_birth, eircode FROM customers LIMIT 3"
```

```
  first_name  |    last_name    |        email         | date_of_birth | eircode
--------------+-----------------+----------------------+---------------+---------
 Emma Carroll | Yasmin Johnston | tok_bcbb4ccc32dbb33e | 1950-01-01    | D08
```

Tokens are the same for the same value everywhere, so the agent can still join and count by customer; `SELECT ... FROM fintech.customers` is denied. Known wart: `fake_name` puts a full name in `first_name` and `last_name` alike.

Edit `work/maskplan.yaml` and run `plan` and `apply --yes` again to see what changes. `docker compose down -v` removes everything.

## Tell us how it went

Whether it worked or not, a few lines help a lot: [open a "Tried it" issue](https://github.com/chauhanprateek89/maskplan/issues/new?template=tried-it.yml). The most useful thing of all is running `maskplan report --role <the role your agent uses>` on a staging copy of a real database: it only reads. Please do not paste real data, names or keys into the issue.
