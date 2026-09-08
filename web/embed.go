package web

import (
	"embed"
	"io/fs"
)

//go:embed all:dist
var distFS embed.FS

// Dist returns the embedded frontend filesystem rooted at dist/.
func Dist() fs.FS {
	sub, err := fs.Sub(distFS, "dist")
	if err != nil {
		return fs.FS(emptyFS{})
	}
	return sub
}

// HasIndex reports whether the embedded frontend contains an index.html,
// i.e. whether the frontend has been built.
func HasIndex() bool {
	_, err := distFS.ReadFile("dist/index.html")
	return err == nil
}

// emptyFS is a minimal empty filesystem used when the frontend has not been
// built yet.
type emptyFS struct{}

func (emptyFS) Open(string) (fs.File, error) {
	return nil, fs.ErrNotExist
}
