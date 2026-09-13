// Command validator-json: membandingkan dua dokumen JSON (ROADMAP 17).
// Flatten sederhana berbasis key-path; setiap perubahan dilaporkan sebagai
// observation json_diff. Status output tetap "observed" — interpretasi
// ada di Hermes, bukan validator.
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
		fmt.Fprintln(os.Stderr, "validator-json:", err)
		os.Exit(1)
	}
	fmt.Printf("validator-json: status=%s observations=%d -> %s\n",
		out.Result.Status, len(out.Observations), *output)
}
