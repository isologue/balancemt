package main

import (
	"database/sql"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestPollingAuthenticationWaitsForSQLiteWriter(t *testing.T) {
	a := newBackupTestApp(t, "polling-test")
	if _, err := a.db.Exec(`INSERT INTO users(id,username,password_hash,created_at) VALUES(1,'test','unused',?)`, time.Now().UTC().Format(time.RFC3339)); err != nil {
		t.Fatal(err)
	}
	if _, err := a.db.Exec(`INSERT INTO sessions(token,user_id,expires_at) VALUES('polling-session',1,?)`, time.Now().Add(time.Hour).UTC().Format(time.RFC3339)); err != nil {
		t.Fatal(err)
	}
	var sequence int
	var schema, path string
	if err := a.db.QueryRow(`PRAGMA database_list`).Scan(&sequence, &schema, &path); err != nil {
		t.Fatal(err)
	}
	writer, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	if _, err := writer.Exec(`BEGIN EXCLUSIVE`); err != nil {
		t.Fatal(err)
	}
	defer writer.Exec(`ROLLBACK`)
	done := make(chan int, 1)
	go func() {
		r := httptest.NewRequest("GET", "/api/accounts", nil)
		r.AddCookie(&http.Cookie{Name: "balancemt_session", Value: "polling-session"})
		w := httptest.NewRecorder()
		a.handleAccounts(w, r)
		done <- w.Code
	}()
	select {
	case status := <-done:
		t.Fatalf("polling request should wait for temporary SQLite writer, got HTTP %d", status)
	case <-time.After(100 * time.Millisecond):
	}
	if _, err := writer.Exec(`COMMIT`); err != nil {
		t.Fatal(err)
	}
	select {
	case status := <-done:
		if status != 200 {
			t.Fatalf("valid polling session returned HTTP %d", status)
		}
	case <-time.After(6 * time.Second):
		t.Fatal("polling did not recover after writer finished")
	}
}
