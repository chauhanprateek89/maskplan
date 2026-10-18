# PostgreSQL with what managed services typically add: pgaudit,
# pg_stat_statements and PostGIS, plus a stand-in for vendor extensions
# that ship SECURITY DEFINER functions. Used by the managed-sim CI job;
# internal/report/managed_test.go creates RDS-like roles itself.
#
#   docker build -t maskplan-managed testdata/managed
#   docker run -d -p 5433:5432 -e POSTGRES_PASSWORD=maskplan maskplan-managed
ARG PG_MAJOR=16
FROM postgres:${PG_MAJOR}
ARG PG_MAJOR
RUN apt-get update \
    && apt-get install -y --no-install-recommends postgresql-${PG_MAJOR}-pgaudit postgresql-${PG_MAJOR}-postgis-3 \
    && rm -rf /var/lib/apt/lists/*
COPY maskplan_sim_managed.control maskplan_sim_managed--1.0.sql /usr/share/postgresql/${PG_MAJOR}/extension/
CMD ["postgres", "-c", "shared_preload_libraries=pgaudit,pg_stat_statements"]
