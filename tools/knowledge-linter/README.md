# Knowledge Linter

`lint.py` validates the deterministic contract for curated entries under
`knowledge/`. It uses only Python's standard library and never fetches citation
URLs or interprets Markdown body text.

## Checks

- required frontmatter fields and scalar types;
- lowercase slug IDs;
- valid lifecycle state and RFC3339 review timestamp;
- `provenance.source` and `provenance.trust`;
- rejection of `untrusted` and `target-controlled` provenance;
- lifecycle state versus official directory consistency;
- duplicate IDs across all official knowledge directories.

The body is treated as data. Security examples, quoted payloads, and prompt-like
text in a reviewed explanation are not executed or used as linter instructions.

```bash
python tools/knowledge-linter/lint.py knowledge/
# or
make lint-knowledge
```

Exit codes:

- `0`: all entries pass;
- `1`: one or more contract violations;
- `2`: invalid command path/usage.
