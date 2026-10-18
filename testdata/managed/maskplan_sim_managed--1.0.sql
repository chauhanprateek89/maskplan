-- Runs as the extension owner, which can read every table.
CREATE FUNCTION sim_managed_table_count() RETURNS bigint
    LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog
    AS 'SELECT count(*) FROM pg_class WHERE relkind = ''r''';
