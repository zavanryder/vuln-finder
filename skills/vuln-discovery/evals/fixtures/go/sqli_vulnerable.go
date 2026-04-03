// Vulnerable: SQL injection via Sprintf into db.Query.
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
	query := fmt.Sprintf("SELECT * FROM products WHERE name LIKE '%%%s%%'", term)
	rows, err := db.Query(query)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	defer rows.Close()
	fmt.Fprintf(w, "results returned")
}

func userHandler(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	row := db.QueryRow("SELECT email FROM users WHERE id = " + id)
	var email string
	row.Scan(&email)
	fmt.Fprintf(w, email)
}
