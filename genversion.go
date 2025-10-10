//go:build exclude

package main

import (
	"html/template"
	"os"
	"os/exec"
	"strings"
)

const tmpl = `package {{.Package}}

const Version = "{{ .Version }}"
const Commit = "{{ .Commit }}"
`

type versinfo struct {
	Package string
	Version string
	Commit  string
}

func main() {
	pack := "main"
	if len(os.Args) > 1 {
		pack = os.Args[1]
	}
	cmd := exec.Command("git", "describe", "--tags", "--always", "--dirty")
	output, err := cmd.Output()
	if err != nil {
		panic(err)
	}
	version := strings.TrimSpace(string(output))

	cmd = exec.Command("git", "rev-parse", "HEAD")
	output, err = cmd.Output()
	if err != nil {
		panic(err)
	}
	commit := strings.TrimSpace(string(output))

	v := versinfo{
		Package: pack,
		Version: version,
		Commit:  string(commit),
	}

	t := template.Must(template.New("version").Parse(tmpl))
	outfile, err := os.Create("version.go")
	if err != nil {
		panic(err)
	}
	defer outfile.Close()
	err = t.Execute(outfile, v)
	if err != nil {
		panic(err)
	}

}
