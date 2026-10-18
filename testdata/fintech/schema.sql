-- A synthetic Irish retail bank, for measuring maskplan scan and as a demo.
-- All data is generated (internal/fintech); no record describes a real
-- person. Ground truth for every column is in labels.yaml next to this file.
-- Tables are created in the current schema (the loader sets search_path).

CREATE TABLE customers (
    id              bigint PRIMARY KEY,
    customer_ref    text NOT NULL,          -- CUS-0000123, shown to the customer
    first_name      text,
    last_name       text,
    date_of_birth   date,
    ppsn            text,                   -- 1234567T
    email           text,                   -- mixed case, some junk
    mobile          text,                   -- added later: NULL in older rows
    home_phone      text,
    address_line_1  text,
    address_line_2  text,
    town            text,
    county          text,
    eircode         text,
    gender          text,
    nationality     text,
    occupation      text,
    annual_income   numeric(12, 2),
    risk_score      integer,
    kyc_status      text,
    kyc_payload     jsonb,                  -- document scan results
    marketing_opt_in boolean,
    created_at      timestamptz
);

CREATE TABLE accounts (
    id              bigint PRIMARY KEY,
    customer_id     bigint NOT NULL,
    iban            text,                   -- printed form: IE29 AIBK 9311 5212 3456 78
    bic             text,
    sort_code       text,                   -- 93-11-52
    account_number  text,                   -- 8 digits
    currency        text,
    balance_cents   bigint,
    opened_on       date,
    status          text
);

CREATE TABLE cards (
    id              bigint PRIMARY KEY,
    account_id      bigint NOT NULL,
    pan             bigint,                 -- stored as a number
    pan_last4       text,
    cardholder_name text,
    expiry_month    smallint,
    expiry_year     smallint,
    network         text,
    status          text
);

CREATE TABLE payees (
    id              bigint PRIMARY KEY,
    customer_id     bigint NOT NULL,
    payee_name      text,
    payee_iban      text,                   -- electronic form, no spaces
    reference       text,
    created_at      timestamptz
);

CREATE TABLE transactions (
    id                bigint NOT NULL,
    account_id        bigint NOT NULL,
    booked_at         date NOT NULL,
    amount_cents      bigint,
    currency          text,
    counterparty_name text,
    counterparty_iban text,                 -- IE, GB, DE, FR, NL
    description       text,                 -- "Transfer to J Murphy", "CARD PAYMENT TESCO"
    merchant_category integer,
    terminal_id       text,                 -- 8 digits: looks like a phone number
    device_ip         inet,
    channel           text
) PARTITION BY RANGE (booked_at);

CREATE TABLE support_tickets (
    id              bigint PRIMARY KEY,
    customer_id     bigint,
    contact_value   text,                   -- email address the customer wrote from
    callback        text,                   -- phone number to call back
    subject         text,
    body            text,
    created_at      timestamptz
);

CREATE TABLE login_events (
    id              bigint PRIMARY KEY,
    customer_id     bigint,
    source_addr     text,                   -- IP address as text
    user_agent      text,
    occurred_at     timestamptz,
    success         boolean
);

CREATE TABLE staff (
    id              integer PRIMARY KEY,
    staff_no        text,                   -- E10023
    display_name    text,
    work_email      text,
    extension       text,                   -- 4 digits
    msisdn          bigint                  -- work mobile, stored as a number: 353871234567
);

CREATE TABLE card_disputes (
    id              bigint PRIMARY KEY,
    card            text,                   -- PAN as typed by an agent: 5500 0000 0000 0004
    opened_at       timestamptz,
    amount_cents    bigint,
    reason          text,
    notes           text
);

CREATE TABLE legacy_import (
    row_no          integer PRIMARY KEY,
    col_a           text,                   -- IBANs, from a spreadsheet with no headers
    col_b           text,                   -- card numbers with dashes
    col_c           text,                   -- order references: 16 digits, not cards
    col_d           text,                   -- amounts
    imported_at     timestamptz
);

CREATE TABLE products (
    id              integer PRIMARY KEY,
    name            text,
    ean             text,                   -- 13-digit barcode
    fee_cents       bigint,
    description     text
);

CREATE TABLE fx_rates (
    rate_date       date,
    from_currency   text,
    to_currency     text,
    rate            numeric(18, 8),
    batch_no        bigint                  -- 10 digits
);

CREATE TABLE transactions_2025_q1 PARTITION OF transactions FOR VALUES FROM ('2025-01-01') TO ('2025-04-01');
CREATE TABLE transactions_2025_q2 PARTITION OF transactions FOR VALUES FROM ('2025-04-01') TO ('2025-07-01');
CREATE TABLE transactions_2025_q3 PARTITION OF transactions FOR VALUES FROM ('2025-07-01') TO ('2025-10-01');
CREATE TABLE transactions_2025_q4 PARTITION OF transactions FOR VALUES FROM ('2025-10-01') TO ('2026-01-01');

-- Refreshed by the loader after the data is in.
CREATE MATERIALIZED VIEW monthly_net AS
    SELECT account_id, date_trunc('month', booked_at)::date AS month, sum(amount_cents) AS net_cents
    FROM transactions GROUP BY 1, 2
    WITH NO DATA;
