package cmd

import (
	"fmt"
	"runtime"
)

var (
	CLIVersion string = "0.0.0"
	Commit     string = "experimental"
	Built      string = "n/a"
)

func Version() {
	s := `  Version:         %s
  Go version:      %s
  Commit:          %s
  Built:           %s
  OS/Arch:         %s/%s
`
	fmt.Printf(s,
		CLIVersion,
		runtime.Version(),
		Commit,
		Built,
		runtime.GOOS, runtime.GOARCH)
}
