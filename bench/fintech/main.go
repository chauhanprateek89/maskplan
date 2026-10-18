// Command fintech loads the synthetic Irish bank in testdata/fintech into a
// Postgres database, for demos and for measuring scan:
//
//	go run ./bench/fintech -dsn postgres://... -customers 10000
//	go run ./bench/accuracy -dsn postgres://... -truth testdata/fintech/labels.yaml
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/chauhanprateek89/maskplan/internal/fintech"
)

func main() {
	dsn := flag.String("dsn", os.Getenv("MASKPLAN_DSN"), "target database")
	schemaSQL := flag.String("schema-sql", "testdata/fintech/schema.sql", "schema DDL")
	schema := flag.String("schema", "fintech", "schema to create; dropped first")
	customers := flag.Int("customers", 10000, "customers; other tables scale with it")
	seed := flag.Uint64("seed", 1, "random seed")
	flag.Parse()
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, *dsn)
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close(ctx)
	start := time.Now()
	if err := fintech.Load(ctx, conn, *schemaSQL, fintech.Options{Schema: *schema, Customers: *customers, Seed: *seed}); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("loaded schema %s with %d customers in %.1f s\n", *schema, *customers, time.Since(start).Seconds())
}
