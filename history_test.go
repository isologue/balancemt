package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestHistoryFiltersBeforeLimitAndPreservesFullError(t *testing.T) {
	a := newBackupTestApp(t, "history-test")
	account, err := a.createAccount(backupTestAccount())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Format(time.RFC3339)
	if _, err := a.db.Exec(`INSERT INTO users(id,username,password_hash,created_at) VALUES(1,'test','unused',?)`, now); err != nil {
		t.Fatal(err)
	}
	if _, err := a.db.Exec(`INSERT INTO sessions(token,user_id,expires_at) VALUES('history-session',1,?)`, time.Now().Add(time.Hour).UTC().Format(time.RFC3339)); err != nil {
		t.Fatal(err)
	}
	fullError := "HTTP401: missing New-Api-User\n" + strings.Repeat("upstream detail <html> & trace\n", 200)
	insert := func(status, message string) {
		t.Helper()
		if _, err := a.db.Exec(`INSERT INTO balance_history(account_id,balance,status,error,checked_at) VALUES(?,12.5,?,?,?)`, account, status, message, now); err != nil {
			t.Fatal(err)
		}
	}
	insert("error", fullError)
	for i := 0; i < 100; i++ {
		insert("ok", "")
	}
	call := func(method, query string, authenticated bool) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, "/api/history"+query, nil)
		if authenticated {
			r.AddCookie(&http.Cookie{Name: "balancemt_session", Value: "history-session"})
		}
		w := httptest.NewRecorder()
		a.handleHistory(w, r)
		return w
	}
	type entry struct {
		Status string `json:"status"`
		Error  string `json:"error"`
	}
	read := func(query string) []entry {
		t.Helper()
		w := call("GET", query, true)
		if w.Code != 200 {
			t.Fatalf("history status: %d", w.Code)
		}
		if w.Header().Get("Cache-Control") != "no-store" {
			t.Fatal("history should not be cached")
		}
		var entries []entry
		if err := json.Unmarshal(w.Body.Bytes(), &entries); err != nil {
			t.Fatal(err)
		}
		return entries
	}
	errors := read("?status=error")
	if len(errors) != 1 || errors[0].Error != fullError {
		t.Fatal("older failure was hidden by newer successes or error was truncated")
	}
	for _, item := range read("") {
		if item.Status != "ok" {
			t.Fatal("default history must preserve latest mixed-record behavior")
		}
	}
	for i := 0; i < 90; i++ {
		insert("error", fmt.Sprintf("failure-%d", i))
	}
	errors = read("?status=error")
	if len(errors) != 20 || errors[0].Error != "failure-89" || errors[19].Error != "failure-70" {
		t.Fatal("failure history must return latest 20 failures in insertion order")
	}
	if count := len(read("?status=ok")); count != 80 {
		t.Fatalf("success history: %d", count)
	}
	for _, tc := range []struct {
		method, query string
		authenticated bool
		want          int
	}{
		{"GET", "", false, 401}, {"POST", "", true, 405}, {"GET", "?status=invalid", true, 400},
		{"DELETE", "?status=error", false, 401}, {"DELETE", "", true, 400}, {"DELETE", "?status=ok", true, 400},
	} {
		if got := call(tc.method, tc.query, tc.authenticated).Code; got != tc.want {
			t.Fatalf("%s %s returned %d, want %d", tc.method, tc.query, got, tc.want)
		}
	}
	var count int
	if err := a.db.QueryRow(`SELECT COUNT(*) FROM balance_history`).Scan(&count); err != nil || count != 120 {
		t.Fatal("history reads or rejected deletes changed stored data")
	}
	for i := 0; i < 2; i++ {
		if w := call("DELETE", "?status=error", true); w.Code != http.StatusOK {
			t.Fatalf("clear history failed: %d", w.Code)
		}
		if len(read("?status=error")) != 0 {
			t.Fatal("clear left failure records")
		}
		if err := a.db.QueryRow(`SELECT COUNT(*) FROM balance_history WHERE status='ok'`).Scan(&count); err != nil || count != 100 {
			t.Fatal("clear removed success history")
		}
	}
	insert("error", fullError)
	if entries := read("?status=error"); len(entries) != 1 || entries[0].Error != fullError {
		t.Fatal("new failures must be recorded after clearing")
	}
}

func TestFailureRetentionMigratesOldHistoryAndAppliesToNewChecks(t *testing.T) {
	a := newBackupTestApp(t, "history-migration-test")
	first, err := a.createAccount(backupTestAccount())
	if err != nil {
		t.Fatal(err)
	}
	second, err := a.createAccount(backupTestAccount())
	if err != nil {
		t.Fatal(err)
	}
	// Reproduce a database created before retention existed, including two accounts.
	if _, err := a.db.Exec(`DROP TRIGGER retain_recent_failures`); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 35; i++ {
		id := first
		if i%2 == 0 {
			id = second
		}
		if _, err := a.db.Exec(`INSERT INTO balance_history(account_id,balance,status,error,checked_at) VALUES(?,1,'error',?,'2026-11-19T00:00:00Z')`, id, fmt.Sprintf("old-%d", i)); err != nil {
			t.Fatal(err)
		}
		if _, err := a.db.Exec(`INSERT INTO balance_history(account_id,balance,status,checked_at) VALUES(?,1,'ok','2026-11-19T00:00:00Z')`, id); err != nil {
			t.Fatal(err)
		}
	}
	assertHistory := func(wantNewest, wantOldest string) {
		t.Helper()
		var failures, successes int
		if err := a.db.QueryRow(`SELECT COUNT(*) FROM balance_history WHERE status='error'`).Scan(&failures); err != nil {
			t.Fatal(err)
		}
		if err := a.db.QueryRow(`SELECT COUNT(*) FROM balance_history WHERE status='ok'`).Scan(&successes); err != nil {
			t.Fatal(err)
		}
		if failures != 20 || successes != 35 {
			t.Fatalf("failures=%d successes=%d", failures, successes)
		}
		var newest, oldest string
		if err := a.db.QueryRow(`SELECT error FROM balance_history WHERE status='error' ORDER BY id DESC LIMIT 1`).Scan(&newest); err != nil {
			t.Fatal(err)
		}
		if err := a.db.QueryRow(`SELECT error FROM balance_history WHERE status='error' ORDER BY id ASC LIMIT 1`).Scan(&oldest); err != nil {
			t.Fatal(err)
		}
		if newest != wantNewest || oldest != wantOldest {
			t.Fatal("retention did not keep the newest failures")
		}
	}
	if err := initDB(a.db); err != nil {
		t.Fatal(err)
	}
	assertHistory("old-34", "old-15")
	// Repeated startup is harmless, and the real failed-check write follows the same limit.
	if err := initDB(a.db); err != nil {
		t.Fatal(err)
	}
	assertHistory("old-34", "old-15")
	fullError := fmt.Errorf("new failure: %s", strings.Repeat("trace <detail> & request\n", 200))
	a.updateCheckState(Account{ID: first, Balance: 5}, "error", fullError)
	assertHistory(fullError.Error(), "old-16")
	var status, lastError string
	if err := a.db.QueryRow(`SELECT status,last_error FROM accounts WHERE id=?`, first).Scan(&status, &lastError); err != nil {
		t.Fatal(err)
	}
	if status != "error" || lastError != fullError.Error() {
		t.Fatal("current account failure state was changed")
	}
}
