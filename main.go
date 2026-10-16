// netcheck diagnoses home networks. The code lives in internal/cli and
// the other internal packages; this file only holds the version.
package main

import "github.com/tworjaga/netcheck/internal/cli"

const version = "0.10.0"

func main() { cli.Main(version) }
