// Command validator-http: membandingkan dua HTTP response (ROADMAP 17 —
// Docker Execution Contract). Input validation-task.json berisi input
// {response_a, response_b} dengan tiap response {status, headers{}, body};
// output validation-result.json berisi status "observed" + observations
// {status_diff|header_diff|body_diff}.
//
// Validator hanya menghasilkan observation — bukan keputusan vulnerability
// (ROADMAP 17: Validator = observation, Hermes = interpretation).
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
		fmt.Fprintln(os.Stderr, "validator-http:", err)
		os.Exit(1)
	}
	fmt.Printf("validator-http: status=%s observations=%d -> %s\n",
		out.Result.Status, len(out.Observations), *output)
}
