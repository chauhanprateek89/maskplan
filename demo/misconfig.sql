-- support_bot answers customer tickets. It was meant to read ticket
-- metadata and nothing else. Five ordinary mistakes later, it reads more.
-- All data is synthetic.

-- Start over if loaded before.
DROP SCHEMA IF EXISTS reporting CASCADE;
DO $$
DECLARE r text;
BEGIN
  FOREACH r IN ARRAY ARRAY['support_bot', 'analytics_readers'] LOOP
    IF EXISTS (SELECT FROM pg_roles WHERE rolname = r) THEN
      EXECUTE format('DROP OWNED BY %I', r);
      EXECUTE format('DROP ROLE %I', r);
    END IF;
  END LOOP;
END $$;

CREATE ROLE support_bot LOGIN PASSWORD 'demo-only';
GRANT USAGE ON SCHEMA fintech TO support_bot;

-- 1. A column grant for ticket metadata that also lists the callback number.
GRANT SELECT (id, customer_id, subject, created_at, callback) ON fintech.support_tickets TO support_bot;

-- 2. Someone added the bot to the dashboards role, which reads transactions.
CREATE ROLE analytics_readers NOLOGIN;
GRANT USAGE ON SCHEMA fintech TO analytics_readers;
GRANT SELECT ON fintech.transactions TO analytics_readers;
GRANT analytics_readers TO support_bot;

-- 3. A "masked" contacts view: an unkeyed hash, and the mobile left as is.
CREATE SCHEMA reporting;
CREATE VIEW reporting.customer_contacts AS
  SELECT id, md5(email) AS email_hash, mobile FROM fintech.customers;
GRANT USAGE ON SCHEMA reporting TO support_bot;
GRANT SELECT ON reporting.customer_contacts TO support_bot;

-- 4. A lookup helper that runs with its owner's rights.
CREATE FUNCTION reporting.customer_email(customer bigint) RETURNS text
  LANGUAGE sql STABLE SECURITY DEFINER
  AS 'SELECT email FROM fintech.customers WHERE id = customer';
REVOKE EXECUTE ON FUNCTION reporting.customer_email(bigint) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION reporting.customer_email(bigint) TO support_bot;

-- 5. Every table created in fintech from now on is readable by dashboards.
ALTER DEFAULT PRIVILEGES IN SCHEMA fintech GRANT SELECT ON TABLES TO analytics_readers;
