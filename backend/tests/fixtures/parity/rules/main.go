package main

import (
	"crypto/tls"
	"database/sql"
	"net/http"
)

func client() *http.Client {
	return &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
}

func remove(db *sql.DB, id string) {
	db.Exec("DELETE FROM sessions WHERE id = '" + id + "'")
}

func safe(db *sql.DB, id string) {
	db.Exec("DELETE FROM sessions WHERE id = $1", id)
}

func pick(xs []int) int {
	for _, x := range xs {
		if x > 0 && x%2 == 0 {
			return x
		}
	}
	return 0
}
