package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func storageLogin(t *testing.T, a *app) {
	t.Helper()
	now := time.Now().UTC().Format(time.RFC3339)
	if _, err := a.db.Exec(`INSERT INTO users(id,username,password_hash,created_at) VALUES(1,'test','unused',?)`, now); err != nil {
		t.Fatal(err)
	}
	if _, err := a.db.Exec(`INSERT INTO sessions(token,user_id,expires_at) VALUES('storage-test-session',1,?)`, time.Now().Add(time.Hour).UTC().Format(time.RFC3339)); err != nil {
		t.Fatal(err)
	}
}

func storageRequest(a *app, method, path, body string, auth bool) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	if auth {
		r.AddCookie(&http.Cookie{Name: "balancemt_session", Value: "storage-test-session"})
	}
	w := httptest.NewRecorder()
	if strings.HasSuffix(path, "/cleanup") {
		a.handleStorageCleanup(w, r)
	} else {
		a.handleStorage(w, r)
	}
	return w
}

func TestSuccessfulChecksUpdateAccountWithoutHistory(t *testing.T) {
	a := newBackupTestApp(t, "success-state-test")
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"data":{"quota":4500000}}`)
	}))
	defer server.Close()
	a.httpClient = server.Client()
	input := backupTestAccount()
	input.BaseURL = server.URL
	id, err := a.createAccount(input)
	if err != nil {
		t.Fatal(err)
	}
	a.updateCheckState(Account{ID: id, Balance: 4}, "error", fmt.Errorf("previous failure"))
	for i := 0; i < 3; i++ {
		result, err := a.checkAccount(id)
		if err != nil {
			t.Fatal(err)
		}
		if result.Balance != 9 || result.Status != "ok" || result.Error != "" || result.LastCheckedAt == "" {
			t.Fatal("successful check did not update account")
		}
	}
	var balance float64
	var status, lastError, lastChecked string
	if err := a.db.QueryRow(`SELECT balance,status,COALESCE(last_error,''),last_checked_at FROM accounts WHERE id=?`, id).Scan(&balance, &status, &lastError, &lastChecked); err != nil {
		t.Fatal(err)
	}
	if balance != 9 || status != "ok" || lastError != "" || lastChecked == "" || calls != 3 {
		t.Fatal("latest successful state was not persisted")
	}
	var successes, failures int
	a.db.QueryRow(`SELECT COUNT(*) FROM balance_history WHERE status='ok'`).Scan(&successes)
	a.db.QueryRow(`SELECT COUNT(*) FROM balance_history WHERE status='error'`).Scan(&failures)
	if successes != 0 || failures != 1 {
		t.Fatalf("successful checks created history or lost errors: successes=%d failures=%d", successes, failures)
	}
}

func TestStorageCleanupPreservesConfigurationAndCompacts(t *testing.T) {
	a := newBackupTestApp(t, "storage-cleanup-test")
	storageLogin(t, a)
	id, err := a.createAccount(backupTestAccount())
	if err != nil {
		t.Fatal(err)
	}
	a.updateCheckState(Account{ID: id, Balance: 5}, "error", fmt.Errorf("current error"))
	var secretBefore string
	if err := a.db.QueryRow(`SELECT secret_enc FROM accounts WHERE id=?`, id).Scan(&secretBefore); err != nil {
		t.Fatal(err)
	}
	if _, err := a.db.Exec(`INSERT INTO app_settings(key,value_enc,updated_at) VALUES('alerts','untouched','2026-11-19T00:00:00Z')`); err != nil {
		t.Fatal(err)
	}
	if _, err := a.db.Exec(`INSERT INTO sessions(token,user_id,expires_at) VALUES('expired',1,?)`, time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)); err != nil {
		t.Fatal(err)
	}
	// Simulate legacy mixed history, including more than twenty failures.
	if _, err := a.db.Exec(`DROP TRIGGER retain_recent_failures`); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 150; i++ {
		if _, err := a.db.Exec(`INSERT INTO balance_history(account_id,balance,status,error,checked_at) VALUES(?,1,'ok',?,?)`, id, strings.Repeat("trace", 6000), time.Now().UTC().Format(time.RFC3339)); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < 35; i++ {
		if _, err := a.db.Exec(`INSERT INTO balance_history(account_id,balance,status,error,checked_at) VALUES(?,1,'error',?,'2026-11-19T00:00:00Z')`, id, fmt.Sprintf("failure-%d", i)); err != nil {
			t.Fatal(err)
		}
	}
	path, err := a.databasePath()
	if err != nil {
		t.Fatal(err)
	}
	backup := filepath.Join(filepath.Dir(path), "manual-backup.db")
	if err := os.WriteFile(backup, []byte("keep this backup"), 0600); err != nil {
		t.Fatal(err)
	}
	before, err := a.storageSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	if before.SuccessRecords != 150 || before.FailureRecords != 36 || before.ExpiredSessions != 1 || before.OtherDataBytes != 16 || before.DiskAvailableBytes == 0 {
		t.Fatal("incorrect initial storage statistics")
	}
	result, err := a.runStorageCleanup(true, true)
	if err != nil {
		t.Fatal(err)
	}
	if result.SuccessDeleted != 150 || result.FailureDeleted != 16 || result.SessionsDeleted != 1 || !result.Compacted || result.ReclaimedBytes <= 0 {
		t.Fatalf("cleanup result: %+v", result)
	}
	after, err := a.storageSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	if after.SuccessRecords != 0 || after.FailureRecords != 20 || after.ExpiredSessions != 0 || after.LastCleanup == nil || after.DatabaseBytes >= before.DatabaseBytes {
		t.Fatal("cleanup statistics did not update")
	}
	var secretAfter, status, lastError, alerts string
	if err := a.db.QueryRow(`SELECT secret_enc,status,last_error FROM accounts WHERE id=?`, id).Scan(&secretAfter, &status, &lastError); err != nil {
		t.Fatal(err)
	}
	if secretBefore != secretAfter || status != "error" || lastError != "current error" {
		t.Fatal("cleanup changed account state or secret")
	}
	if err := a.db.QueryRow(`SELECT value_enc FROM app_settings WHERE key='alerts'`).Scan(&alerts); err != nil || alerts != "untouched" {
		t.Fatal("cleanup modified alert settings")
	}
	var users, active int
	a.db.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&users)
	a.db.QueryRow(`SELECT COUNT(*) FROM sessions WHERE token='storage-test-session'`).Scan(&active)
	if users != 1 || active != 1 {
		t.Fatal("cleanup removed users or active sessions")
	}
	if b, err := os.ReadFile(backup); err != nil || string(b) != "keep this backup" {
		t.Fatal("cleanup removed or changed backup")
	}
	result, err = a.runStorageCleanup(true, true)
	if err != nil || result.SuccessDeleted != 0 || result.FailureDeleted != 0 || result.SessionsDeleted != 0 {
		t.Fatal("repeated cleanup was not idempotent")
	}
}

func TestStorageAPIValidationSchedulingAndBusyState(t *testing.T) {
	a := newBackupTestApp(t, "storage-api-test")
	storageLogin(t, a)
	for _, tc := range []struct {
		method, path, body string
		auth               bool
		want               int
	}{
		{"GET", "/api/settings/storage", "", false, 401},
		{"PUT", "/api/settings/storage", `{"enabled":true,"interval_hours":24}`, false, 401},
		{"POST", "/api/settings/storage/cleanup", `{"compact":true}`, false, 401},
		{"POST", "/api/settings/storage", "", true, 405},
		{"GET", "/api/settings/storage/cleanup", "", true, 405},
		{"PUT", "/api/settings/storage", `{"enabled":true,"interval_hours":0}`, true, 400},
		{"PUT", "/api/settings/storage", `{"enabled":true,"interval_hours":169}`, true, 400},
		{"POST", "/api/settings/storage/cleanup", "bad json", true, 400},
	} {
		if w := storageRequest(a, tc.method, tc.path, tc.body, tc.auth); w.Code != tc.want {
			t.Fatalf("%s %s returned %d, want %d", tc.method, tc.path, w.Code, tc.want)
		}
	}
	w := storageRequest(a, "GET", "/api/settings/storage", "", true)
	var stats storageStats
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &stats) != nil || !stats.Settings.Enabled || stats.Settings.IntervalHours != 24 || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("default storage policy or statistics response invalid")
	}
	// First startup must execute; the next timer pass must skip until it is due.
	first, err := a.runStorageCleanup(false, false)
	if err != nil || first == nil {
		t.Fatal("initial automatic cleanup did not run")
	}
	if result, err := a.runStorageCleanup(false, false); err != nil || result != nil {
		t.Fatal("automatic cleanup repeated before its interval")
	}
	stored, err := a.readStorageSettings()
	if err != nil {
		t.Fatal(err)
	}
	stored.LastAttemptAt = time.Now().Add(-25 * time.Hour).UTC().Format(time.RFC3339)
	if err := a.saveStorageSettings(stored); err != nil {
		t.Fatal(err)
	}
	if result, err := a.runStorageCleanup(false, false); err != nil || result == nil {
		t.Fatal("overdue automatic cleanup did not run")
	}
	w = storageRequest(a, "PUT", "/api/settings/storage", `{"enabled":false,"interval_hours":2}`, true)
	if w.Code != 200 {
		t.Fatal("cannot save storage settings")
	}
	// Verify persistence through another app instance sharing the database and key.
	another := &app{db: a.db, key: a.key}
	saved, err := another.readStorageSettings()
	if err != nil || saved.Policy.Enabled || saved.Policy.IntervalHours != 2 {
		t.Fatal("storage policy not persisted")
	}
	if result, err := a.runStorageCleanup(false, false); err != nil || result != nil {
		t.Fatal("disabled schedule ran")
	}
	if w := storageRequest(a, "POST", "/api/settings/storage/cleanup", `{"compact":false}`, true); w.Code != 200 {
		t.Fatal("manual cleanup must work while schedule is disabled")
	}
	a.storageMu.Lock()
	busyCleanup := storageRequest(a, "POST", "/api/settings/storage/cleanup", `{"compact":false}`, true)
	busySave := storageRequest(a, "PUT", "/api/settings/storage", `{"enabled":true,"interval_hours":24}`, true)
	a.storageMu.Unlock()
	if busyCleanup.Code != 409 || busySave.Code != 409 {
		t.Fatal("concurrent maintenance was not rejected")
	}
	w = storageRequest(a, "PUT", "/api/settings/storage", `{"enabled":true,"interval_hours":3}`, true)
	if w.Code != 200 {
		t.Fatal("cannot re-enable automatic cleanup")
	}
	stored, err = a.readStorageSettings()
	if err != nil {
		t.Fatal(err)
	}
	if nextStorageCleanup(stored).Before(time.Now().Add(2 * time.Hour)) {
		t.Fatal("re-enabled cleanup was not rescheduled")
	}
}
