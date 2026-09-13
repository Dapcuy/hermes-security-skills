// Command validator-openapi: mem-parsing OpenAPI spec JSON dan melaporkan
// fields wajib yang hilang (info.title, info.version, paths) — ROADMAP 17.
// Validator hanya menghasilkan observation, bukan keputusan vulnerability.
package main

import (
	"flag"
	"fmt"
	"os"
)

func main() {
	input := flag.String("input", "/workspace/input/validation-task.json", "path validation-task.json")
	output := flag.String("output", "/workspace/output/validation-result.json", "path validation-result.json")
	flag.Parse()

	out, err := Run(*input, *output)
	if err != nil {
		fmt.Fprintln(os.Stderr, "validator-openapi:", err)
		os.Exit(1)
	}
	fmt.Printf("validator-openapi: status=%s observations=%d -> %s\n",
		out.Result.Status, len(out.Observations), *output)
}
