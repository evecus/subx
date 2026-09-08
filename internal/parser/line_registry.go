package parser

import "strings"

// The line parsers must be registered in the same priority order as
// Sub-Store's parser list: Surge first, then Loon, then Quantumult X.
// Parsers that fail (Test mismatch or Parse error) fall through to the
// next one, which is how lines using Loon-only syntax are handed over
// from the Surge parser.
func init() {
	MustRegister(
		&Parser{Name: "Surge Line Parser",
			Test:  surgeLineTest,
			Parse: parseSurgeLine,
		},
		&Parser{Name: "Loon Line Parser",
			Test:  loonLineTest,
			Parse: parseLoonLine,
		},
		&Parser{Name: "QX Line Parser",
			Test: func(line string) bool {
				// mirrors the QX_* parser tests (e.g. index.js:2606-2611):
				// line.split(',')[0].trim() must match /^<type>\s*=/
				first := strings.TrimSpace(strings.SplitN(line, ",", 2)[0])
				eq := strings.Index(first, "=")
				if eq == -1 {
					return false
				}
				return qxTypes[strings.TrimSpace(first[:eq])]
			},
			Parse: parseQXLine,
		},
	)
}
