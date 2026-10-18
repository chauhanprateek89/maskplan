// Command genvectors regenerates testdata/vectors.json from the Go reference
// implementation. Run it from the repository root: go run ./cmd/genvectors
package main

import (
	"log"
	"os"

	"github.com/chauhanprateek89/maskplan/internal/vectors"
)

func main() {
	out := "testdata/vectors.json"
	if len(os.Args) > 1 {
		out = os.Args[1]
	}
	data, err := vectors.Marshal(vectors.Generate())
	if err != nil {
		log.Fatal(err)
	}
	if err := os.WriteFile(out, data, 0o644); err != nil {
		log.Fatal(err)
	}
	log.Printf("wrote %s", out)
}
