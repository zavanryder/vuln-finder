// Vulnerable: Path traversal via user-controlled filename in file serve.
package main

import (
	"net/http"
	"os"
	"path/filepath"
)

const baseDir = "/var/data/files"

func downloadHandler(w http.ResponseWriter, r *http.Request) {
	filename := r.URL.Query().Get("name")
	path := filepath.Join(baseDir, filename)
	data, err := os.ReadFile(path)
	if err != nil {
		http.Error(w, "not found", 404)
		return
	}
	w.Write(data)
}
