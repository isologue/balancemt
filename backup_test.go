package main

import (
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func newBackupTestApp(t *testing.T, keyText string) *app {
	t.Helper()
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if err := initDB(db); err != nil {
		t.Fatal(err)
	}
	key := sha256.Sum256([]byte(keyText))
	return &app{db: db, key: key[:], monitorInterval: 10 * time.Second, alerts: alertConfig{SMTPPort: 587}, intervalWake: make(chan struct{}, 1), alertStates: make(map[int64]alertState)}
}

func backupTestAccount() accountInput {
	enabled := false
	return accountInput{Name: "CC", Provider: "generic", BaseProvider: "new-api", BaseURL: "https://example.test", Identifier: "test-user", APIUserID: "541", Password: "station-secret", AccessToken: "station-token", Currency: "USD", Threshold: 12.34, Enabled: &enabled,
		LoginPath: "/api/user/login?turnstile=", BalancePath: "/api/user/self", IdentifierKey: "username", TokenField: "data.access_token", BalanceField: "data.quota", BalanceScale: 500000}
}

func backupTestPayload(t *testing.T, a *app) backupPayload {
	t.Helper()
	if _, err := a.createAccount(backupTestAccount()); err != nil {
		t.Fatal(err)
	}
	a.alerts = alertConfig{SMTPHost: "smtp.example.test", SMTPPort: 465, SMTPUsername: "mailer", SMTPPassword: "smtp-secret", SMTPFrom: "from@example.test", EmailTo: []string{"to@example.test"}, SMSProvider: "webhook", SMSTo: "+12345678", SMSWebhookURL: "https://sms.example.test", SMSWebhookToken: "sms-secret", TwilioAccountSID: "twilio-id", TwilioAuthToken: "twilio-secret", TwilioFrom: "+99999999"}
	a.monitorInterval = 37 * time.Second
	payload, err := a.snapshotBackup()
	if err != nil {
		t.Fatal(err)
	}
	return payload
}

func TestPortableBackupAcrossDifferentKeys(t *testing.T) {
	source := newBackupTestApp(t, "source-key")
	destination := newBackupTestApp(t, "different-destination-key")
	payload := backupTestPayload(t, source)
	backup, err := sealBackup(payload)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(backup)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"station-secret", "station-token", "smtp-secret", "sms-secret", "twilio-secret", "test-user", "example.test"} {
		if strings.Contains(string(raw), secret) {
			t.Fatal("export contains plaintext configuration or credentials")
		}
	}
	if strings.Contains(string(raw), `"data"`) || strings.Contains(string(raw), `"accounts"`) || strings.Contains(string(raw), `"settings"`) {
		t.Fatal("export exposes plaintext payload")
	}
	second, err := sealBackup(payload)
	if err != nil || string(second.Nonce) == string(backup.Nonce) || string(second.Ciphertext) == string(backup.Ciphertext) {
		t.Fatal("repeated exports must use fresh encryption nonces")
	}
	restored, err := readBackup(raw)
	if err != nil {
		t.Fatal(err)
	}
	result, err := destination.importBackup(restored, "skip", true)
	if err != nil {
		t.Fatal(err)
	}
	if result.Added != 1 || !result.AlertsImported {
		t.Fatalf("unexpected counts: %+v", result)
	}
	snapshot, err := destination.snapshotBackup()
	if err != nil {
		t.Fatal(err)
	}
	before, _ := json.Marshal(payload.Accounts)
	after, _ := json.Marshal(snapshot.Accounts)
	if string(before) != string(after) {
		t.Fatal("station fields or credentials were not fully preserved")
	}
	before, _ = json.Marshal(payload.Settings)
	after, _ = json.Marshal(snapshot.Settings)
	if string(before) != string(after) {
		t.Fatal("alert settings were not fully preserved")
	}
	var encrypted string
	if err := destination.db.QueryRow(`SELECT secret_enc FROM accounts`).Scan(&encrypted); err != nil {
		t.Fatal(err)
	}
	if _, err := source.decrypt(encrypted); err == nil {
		t.Fatal("destination credentials still use source key")
	}
	restarted := &app{db: destination.db, key: destination.key}
	if err := restarted.loadStoredAlertSettings(); err != nil {
		t.Fatal(err)
	}
	if restarted.currentAlertConfig().SMTPPassword != "smtp-secret" || restarted.currentMonitorInterval() != 37*time.Second {
		t.Fatal("settings did not survive restart")
	}
	select {
	case <-destination.intervalWake:
	default:
		t.Fatal("monitor was not notified")
	}
}

func TestBackupMergeAndOverwrite(t *testing.T) {
	source := newBackupTestApp(t, "source")
	payload := backupTestPayload(t, source)
	destination := newBackupTestApp(t, "destination")
	local := backupTestAccount()
	local.BaseURL += "/"
	local.Name = "existing"
	local.Password = "local-password"
	local.AccessToken = "local-token"
	id, err := destination.createAccount(local)
	if err != nil {
		t.Fatal(err)
	}
	other := backupTestAccount()
	other.Identifier = "another-user"
	other.Name = "unrelated"
	if _, err := destination.createAccount(other); err != nil {
		t.Fatal(err)
	}
	result, err := destination.importBackup(payload, "skip", false)
	if err != nil {
		t.Fatal(err)
	}
	if result.Skipped != 1 || result.Added != 0 || result.Updated != 0 {
		t.Fatalf("unexpected skip result: %+v", result)
	}
	if destination.currentMonitorInterval() != 10*time.Second || destination.currentAlertConfig().SMTPHost != "" {
		t.Fatal("alerts changed without opt-in")
	}
	destination.db.Exec(`UPDATE accounts SET balance=99,status='ok' WHERE id=?`, id)
	result, err = destination.importBackup(payload, "overwrite", true)
	if err != nil {
		t.Fatal(err)
	}
	if result.Updated != 1 || result.Added != 0 {
		t.Fatalf("unexpected overwrite result: %+v", result)
	}
	accounts, err := destination.listAccounts()
	if err != nil {
		t.Fatal(err)
	}
	if len(accounts) != 2 {
		t.Fatal("unrelated account was removed")
	}
	for _, account := range accounts {
		if account.ID == id && (account.Name != "CC" || account.Status != "pending" || account.Balance != 0 || account.APIUserID != "541" || account.Enabled) {
			t.Fatal("overwrite did not restore full station configuration")
		}
	}
	result, err = destination.importBackup(payload, "skip", true)
	if err != nil || result.Skipped != 1 {
		t.Fatal("repeated import was not idempotent")
	}
}

func TestBackupFailureIsAtomic(t *testing.T) {
	source := newBackupTestApp(t, "source")
	payload := backupTestPayload(t, source)
	destination := newBackupTestApp(t, "destination")
	second := backupTestAccount()
	second.Identifier = "second"
	second.Name = "fail-insert"
	payload.Accounts = append(payload.Accounts, second)
	if _, err := destination.db.Exec(`CREATE TRIGGER reject_test BEFORE INSERT ON accounts WHEN NEW.name='fail-insert' BEGIN SELECT RAISE(ABORT,'test insert failure'); END`); err != nil {
		t.Fatal(err)
	}
	if _, err := destination.importBackup(payload, "skip", true); err == nil {
		t.Fatal("expected failed transaction")
	}
	accounts, err := destination.listAccounts()
	if err != nil {
		t.Fatal(err)
	}
	if len(accounts) != 0 || destination.currentMonitorInterval() != 10*time.Second {
		t.Fatal("partial state remained after SQL failure")
	}
	var count int
	destination.db.QueryRow(`SELECT COUNT(*) FROM app_settings`).Scan(&count)
	if count != 0 {
		t.Fatal("settings committed after account failure")
	}
	payload.Accounts[1].BaseURL = "not a URL"
	if _, err := destination.importBackup(payload, "skip", true); err == nil {
		t.Fatal("invalid final account accepted")
	}
	accounts, _ = destination.listAccounts()
	if len(accounts) != 0 {
		t.Fatal("partial state after validation failure")
	}
}

func TestBackupHTTPAuthenticationAndLimits(t *testing.T) {
	a := newBackupTestApp(t, "test")
	for _, handler := range []http.HandlerFunc{a.handleBackupExport, a.handleBackupImport} {
		w := httptest.NewRecorder()
		handler(w, httptest.NewRequest("POST", "/", strings.NewReader(`{}`)))
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("unauthenticated request: %d", w.Code)
		}
	}
	now := time.Now().UTC().Format(time.RFC3339)
	if _, err := a.db.Exec(`INSERT INTO users(id,username,password_hash,created_at) VALUES(1,'test','unused',?)`, now); err != nil {
		t.Fatal(err)
	}
	if _, err := a.db.Exec(`INSERT INTO sessions(token,user_id,expires_at) VALUES('test-session',1,?)`, time.Now().Add(time.Hour).UTC().Format(time.RFC3339)); err != nil {
		t.Fatal(err)
	}
	request := func(method, body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, "/", strings.NewReader(body))
		r.AddCookie(&http.Cookie{Name: "balancemt_session", Value: "test-session"})
		w := httptest.NewRecorder()
		a.handleBackupExport(w, r)
		return w
	}
	if w := request("GET", ""); w.Code != 405 {
		t.Fatalf("unexpected method status: %d", w.Code)
	}
	if w := request("POST", `{} {}`); w.Code != 400 {
		t.Fatal("trailing JSON accepted")
	}
	if w := request("POST", `{"padding":"`+strings.Repeat("x", maxBackupBytes)+`"}`); w.Code != 400 {
		t.Fatal("oversized request accepted")
	}
	w := request("POST", `{}`)
	if w.Code != 200 || w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("Content-Disposition") == "" {
		t.Fatalf("export headers/status invalid: %d", w.Code)
	}
}

func TestPortableBackupRejectsMalformedFiles(t *testing.T) {
	for _, raw := range []string{
		`null`, `{}`, `[]`, `{"format":"other","version":2}`, `{"format":"balancemt-backup","version":99}`,
		`{"format":"balancemt-backup","version":2}`, `{"format":"balancemt-backup","version":2,"data":null}`,
		`{"format":"balancemt-backup","version":2,"data":{"version":1,"accounts":[],"settings":{}}}`,
		`{"format":"balancemt-backup","version":1,"ciphertext":123}`,
	} {
		if _, err := readBackup(json.RawMessage(raw)); err == nil {
			t.Fatalf("malformed backup accepted: %s", raw)
		}
	}
	payload := backupTestPayload(t, newBackupTestApp(t, "test"))
	payload.Accounts[0].Password = strings.Repeat("x", maxBackupBytes/2)
	if _, err := sealBackup(payload); err == nil {
		t.Fatal("backup too large to reimport was exported")
	}
}

func TestPasswordFreeBackupHTTPRoundTrip(t *testing.T) {
	source := newBackupTestApp(t, "source")
	backupTestPayload(t, source)
	destination := newBackupTestApp(t, "destination")
	for _, a := range []*app{source, destination} {
		if _, err := a.db.Exec(`INSERT INTO users(id,username,password_hash,created_at) VALUES(1,'test','unused',?)`, time.Now().UTC().Format(time.RFC3339)); err != nil {
			t.Fatal(err)
		}
		if _, err := a.db.Exec(`INSERT INTO sessions(token,user_id,expires_at) VALUES('test-session',1,?)`, time.Now().Add(time.Hour).UTC().Format(time.RFC3339)); err != nil {
			t.Fatal(err)
		}
	}
	call := func(handler http.HandlerFunc, body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", "/", strings.NewReader(body))
		r.AddCookie(&http.Cookie{Name: "balancemt_session", Value: "test-session"})
		w := httptest.NewRecorder()
		handler(w, r)
		return w
	}
	exported := call(source.handleBackupExport, `{}`)
	if exported.Code != 200 {
		t.Fatalf("password-free export failed: %d", exported.Code)
	}
	var backup encryptedBackup
	if err := json.Unmarshal(exported.Body.Bytes(), &backup); err != nil || backup.Version != backupVersion || backup.Format != backupFormat {
		t.Fatal("export is not the current encrypted format")
	}
	body, _ := json.Marshal(map[string]any{"backup": json.RawMessage(exported.Body.Bytes()), "mode": "skip", "import_alerts": true})
	imported := call(destination.handleBackupImport, string(body))
	var result backupImportResult
	if imported.Code != 200 || json.Unmarshal(imported.Body.Bytes(), &result) != nil || result.Added != 1 || !result.AlertsImported {
		t.Fatalf("password-free import failed: %d", imported.Code)
	}
	snapshot, err := destination.snapshotBackup()
	if err != nil || snapshot.Accounts[0].Password != "station-secret" || snapshot.Settings.Alerts.SMTPPassword != "smtp-secret" {
		t.Fatal("credentials did not survive HTTP roundtrip")
	}
}

func TestEncryptedBackupRejectsTampering(t *testing.T) {
	payload := backupTestPayload(t, newBackupTestApp(t, "source"))
	envelope, err := sealBackup(payload)
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*encryptedBackup){
		"format":               func(b *encryptedBackup) { b.Format = "other" },
		"version":              func(b *encryptedBackup) { b.Version++ },
		"algorithm":            func(b *encryptedBackup) { b.Algorithm = "none" },
		"project key":          func(b *encryptedBackup) { b.KeyID = "other-key" },
		"nonce length":         func(b *encryptedBackup) { b.Nonce = []byte{1} },
		"nonce tampered":       func(b *encryptedBackup) { b.Nonce[0] ^= 1 },
		"ciphertext tampered":  func(b *encryptedBackup) { b.Ciphertext[0] ^= 1 },
		"ciphertext truncated": func(b *encryptedBackup) { b.Ciphertext = b.Ciphertext[:15] },
		"ciphertext oversized": func(b *encryptedBackup) { b.Ciphertext = make([]byte, maxBackupBytes/2+17) },
	} {
		t.Run(name, func(t *testing.T) {
			b := envelope
			b.Nonce = append([]byte(nil), envelope.Nonce...)
			b.Ciphertext = append([]byte(nil), envelope.Ciphertext...)
			mutate(&b)
			raw, err := json.Marshal(b)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := readBackup(raw); err == nil {
				t.Fatal("modified backup accepted")
			}
		})
	}
	payload.Accounts[0].BaseURL = "invalid"
	invalid, err := sealBackup(payload)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(invalid)
	if _, err := readBackup(raw); err == nil {
		t.Fatal("decrypted invalid configuration accepted")
	}
}

func TestBackupImportNormalizesLegacyRelativePaths(t *testing.T) {
	source := newBackupTestApp(t, "legacy-path-source")
	payload := backupTestPayload(t, source)
	payload.Accounts[0].LoginPath = "api/user/login"
	payload.Accounts[0].BalancePath = "api/user/self"

	destination := newBackupTestApp(t, "legacy-path-destination")
	result, err := destination.importBackup(payload, "skip", false)
	if err != nil {
		t.Fatal(err)
	}
	if result.Added != 1 {
		t.Fatalf("added = %d, want 1", result.Added)
	}
	var loginPath, balancePath string
	if err := destination.db.QueryRow(`SELECT login_path,balance_path FROM accounts LIMIT 1`).Scan(&loginPath, &balancePath); err != nil {
		t.Fatal(err)
	}
	if loginPath != "/api/user/login" || balancePath != "/api/user/self" {
		t.Fatalf("paths = %q, %q", loginPath, balancePath)
	}
}
