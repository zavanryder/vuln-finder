// Safe: SQL injection -- parameterized queries with placeholders.
package main

import (
	"database/sql"
	"fmt"
	"net/http"

	_ "github.com/lib/pq"
)

var db *sql.DB

func searchHandler(w http.ResponseWriter, r *http.Request) {
	term := r.URL.Query().Get("q")
	rows, err := db.Query("SELECT * FROM products WHERE name LIKE $1", "%"+term+"%")
	if err != nil {
		http.Error(w, "query error", 500)
		return
	}
	defer rows.Close()
	fmt.Fprintf(w, "results returned")
}

func userHandler(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	row := db.QueryRow("SELECT email FROM users WHERE id = $1", id)
	var email string
	row.Scan(&email)
	fmt.Fprintf(w, "%s", email)
}
