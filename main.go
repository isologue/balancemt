package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"database/sql"
	"embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math"
	"net"
	"net/http"
	"net/smtp"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
	_ "modernc.org/sqlite"
)

//go:embed web/*
var webFS embed.FS

type app struct {
	db               *sql.DB
	storageMu        sync.Mutex
	httpClient       *http.Client
	key              []byte
	mu               sync.Mutex
	alertMu          sync.Mutex
	alertStates      map[int64]alertState
	backupMu         sync.Mutex
	settingsMu       sync.Mutex
	configMu         sync.RWMutex
	monitorInterval  time.Duration
	usageWindowHours int
	alerts           alertConfig
	intervalWake     chan struct{}
}

type alertState struct {
	lowBalance bool
	checkError bool
}

type alertConfig struct {
	SMTPHost         string
	SMTPPort         int
	SMTPUsername     string
	SMTPPassword     string
	SMTPFrom         string
	EmailTo          []string
	SMSProvider      string
	SMSTo            string
	SMSWebhookURL    string
	SMSWebhookToken  string
	TwilioAccountSID string
	TwilioAuthToken  string
	TwilioFrom       string
}

type alertSettingsInput struct {
	MonitorIntervalSeconds int    `json:"monitor_interval_seconds"`
	UsageWindowHours       int    `json:"usage_window_hours"`
	SMTPHost               string `json:"smtp_host"`
	SMTPPort               int    `json:"smtp_port"`
	SMTPUsername           string `json:"smtp_username"`
	SMTPPassword           string `json:"smtp_password"`
	SMTPFrom               string `json:"smtp_from"`
	AlertEmailTo           string `json:"alert_email_to"`
	SMSProvider            string `json:"sms_provider"`
	SMSTo                  string `json:"sms_to"`
	SMSWebhookURL          string `json:"sms_webhook_url"`
	SMSWebhookToken        string `json:"sms_webhook_token"`
	TwilioAccountSID       string `json:"twilio_account_sid"`
	TwilioAuthToken        string `json:"twilio_auth_token"`
	TwilioFrom             string `json:"twilio_from"`
	ClearSMTPPassword      bool   `json:"clear_smtp_password"`
	ClearSMSWebhookToken   bool   `json:"clear_sms_webhook_token"`
	ClearTwilioAuthToken   bool   `json:"clear_twilio_auth_token"`
}

type alertSettingsResponse struct {
	MonitorIntervalSeconds    int    `json:"monitor_interval_seconds"`
	UsageWindowHours          int    `json:"usage_window_hours"`
	SMTPHost                  string `json:"smtp_host"`
	SMTPPort                  int    `json:"smtp_port"`
	SMTPUsername              string `json:"smtp_username"`
	SMTPFrom                  string `json:"smtp_from"`
	AlertEmailTo              string `json:"alert_email_to"`
	EmailConfigured           bool   `json:"email_configured"`
	SMTPPasswordConfigured    bool   `json:"smtp_password_configured"`
	SMSProvider               string `json:"sms_provider"`
	SMSTo                     string `json:"sms_to"`
	SMSWebhookURL             string `json:"sms_webhook_url"`
	SMSWebhookConfigured      bool   `json:"sms_webhook_configured"`
	SMSWebhookTokenConfigured bool   `json:"sms_webhook_token_configured"`
	TwilioAccountSID          string `json:"twilio_account_sid"`
	TwilioFrom                string `json:"twilio_from"`
	TwilioConfigured          bool   `json:"twilio_configured"`
	TwilioAuthTokenConfigured bool   `json:"twilio_auth_token_configured"`
}

type Account struct {
	ID               int64   `json:"id"`
	Name             string  `json:"name"`
	Provider         string  `json:"provider"`
	BaseProvider     string  `json:"base_provider"`
	BaseURL          string  `json:"base_url"`
	Identifier       string  `json:"identifier"`
	APIUserID        string  `json:"api_user_id"`
	Currency         string  `json:"currency"`
	Threshold        float64 `json:"threshold"`
	Enabled          bool    `json:"enabled"`
	Balance          float64 `json:"balance"`
	LastCheckedAt    string  `json:"last_checked_at"`
	Status           string  `json:"status"`
	Error            string  `json:"error,omitempty"`
	LoginPath        string  `json:"login_path"`
	BalancePath      string  `json:"balance_path"`
	IdentifierKey    string  `json:"identifier_key"`
	TokenField       string  `json:"token_field"`
	BalanceField     string  `json:"balance_field"`
	BalanceScale     float64 `json:"balance_scale"`
	CreatedAt        string  `json:"created_at"`
	UsageWindowHours int     `json:"usage_window_hours"`
	Consumption      float64 `json:"consumption"`
	EstimatedHours   float64 `json:"estimated_hours"`
	UsageSamples     int     `json:"usage_samples"`
	UsageReady       bool    `json:"usage_ready"`
}

type balanceUsage struct {
	Consumption    float64
	EstimatedHours float64
	Samples        int
	Ready          bool
}

type accountInput struct {
	Name          string  `json:"name"`
	Provider      string  `json:"provider"`
	BaseProvider  string  `json:"base_provider"`
	BaseURL       string  `json:"base_url"`
	Identifier    string  `json:"identifier"`
	APIUserID     string  `json:"api_user_id"`
	Password      string  `json:"password"`
	AccessToken   string  `json:"access_token"`
	Currency      string  `json:"currency"`
	Threshold     float64 `json:"threshold"`
	Enabled       *bool   `json:"enabled"`
	LoginPath     string  `json:"login_path"`
	BalancePath   string  `json:"balance_path"`
	IdentifierKey string  `json:"identifier_key"`
	TokenField    string  `json:"token_field"`
	BalanceField  string  `json:"balance_field"`
	BalanceScale  float64 `json:"balance_scale"`
}

type accountSecret struct {
	Identifier  string `json:"identifier"`
	Password    string `json:"password"`
	AccessToken string `json:"access_token,omitempty"`
}

type balanceResult struct {
	Balance float64
	Raw     float64
}

func main() {
	dataDir := getenv("DATA_DIR", "./data")
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		log.Fatal(err)
	}
	db, err := sql.Open("sqlite", filepath.Join(dataDir, "balancemt.db"))
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()
	if err := initDB(db); err != nil {
		log.Fatal(err)
	}

	secret := getenv("ENCRYPTION_KEY", "balancemt-local-dev-key")
	key := sha256.Sum256([]byte(secret))
	if secret == "balancemt-local-dev-key" {
		log.Println("WARNING: ENCRYPTION_KEY is not set; using the development key")
	}
	a := &app{
		db:               db,
		key:              key[:],
		httpClient:       &http.Client{Timeout: 25 * time.Second},
		alertStates:      make(map[int64]alertState),
		monitorInterval:  loadMonitorInterval(),
		usageWindowHours: 24,
		alerts:           loadAlertConfig(),
		intervalWake:     make(chan struct{}, 1),
	}
	if err := a.loadStoredAlertSettings(); err != nil {
		log.Printf("load stored alert settings: %v", err)
	}
	log.Printf("balance monitor interval: %s", a.currentMonitorInterval())

	go a.monitorLoop()
	go a.storageMaintenanceLoop()

	mux := http.NewServeMux()
	mux.HandleFunc("/api/auth/status", a.handleAuthStatus)
	mux.HandleFunc("/api/auth/setup", a.handleSetup)
	mux.HandleFunc("/api/auth/login", a.handleLogin)
	mux.HandleFunc("/api/auth/change-password", a.handleChangePassword)
	mux.HandleFunc("/api/auth/logout", a.handleLogout)
	mux.HandleFunc("/api/platforms", a.handlePlatforms)
	mux.HandleFunc("/api/accounts", a.handleAccounts)
	mux.HandleFunc("/api/accounts/", a.handleAccountAction)
	mux.HandleFunc("/api/history", a.handleHistory)
	mux.HandleFunc("/api/settings/storage", a.handleStorage)
	mux.HandleFunc("/api/settings/storage/cleanup", a.handleStorageCleanup)
	mux.HandleFunc("/api/settings/alerts", a.handleAlertSettings)
	mux.HandleFunc("/api/settings/alerts/test", a.handleAlertSettingsTest)
	mux.HandleFunc("/api/settings/backup/export", a.handleBackupExport)
	mux.HandleFunc("/api/settings/backup/import", a.handleBackupImport)
	mux.HandleFunc("/", a.handleWeb)

	addr := getenv("ADDR", ":8080")
	log.Printf("balancemt listening on %s", addr)
	if err := http.ListenAndServe(addr, withSecurityHeaders(withCORS(mux))); err != nil {
		log.Fatal(err)
	}
}

func initDB(db *sql.DB) error {
	// Serialize local reads/writes and wait for short external locks during polling.
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	schema := `
    PRAGMA busy_timeout = 5000;
    PRAGMA journal_mode = DELETE;
    PRAGMA foreign_keys = ON;
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS sessions (
        token TEXT PRIMARY KEY,
        user_id INTEGER NOT NULL,
        expires_at TEXT NOT NULL,
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
    );
    CREATE TABLE IF NOT EXISTS accounts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        provider TEXT NOT NULL,
        base_url TEXT NOT NULL,
        identifier TEXT NOT NULL,
        api_user_id TEXT NOT NULL DEFAULT '',
        secret_enc TEXT NOT NULL,
        currency TEXT NOT NULL DEFAULT 'USD',
        threshold REAL NOT NULL DEFAULT 0,
        enabled INTEGER NOT NULL DEFAULT 1,
        balance REAL NOT NULL DEFAULT 0,
        last_checked_at TEXT,
        status TEXT NOT NULL DEFAULT 'pending',
        last_error TEXT,
        login_path TEXT,
        balance_path TEXT,
        identifier_key TEXT,
        token_field TEXT,
        balance_field TEXT,
        balance_scale REAL NOT NULL DEFAULT 1,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS balance_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        account_id INTEGER NOT NULL,
        balance REAL NOT NULL,
        status TEXT NOT NULL,
        error TEXT,
        checked_at TEXT NOT NULL,
        FOREIGN KEY(account_id) REFERENCES accounts(id) ON DELETE CASCADE
    );
    CREATE INDEX IF NOT EXISTS idx_history_account_time ON balance_history(account_id, checked_at DESC);
    CREATE INDEX IF NOT EXISTS idx_history_status_id ON balance_history(status, id DESC);
    CREATE TABLE IF NOT EXISTS balance_snapshots (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        account_id INTEGER NOT NULL,
        balance REAL NOT NULL,
        checked_at TEXT NOT NULL,
        FOREIGN KEY(account_id) REFERENCES accounts(id) ON DELETE CASCADE
    );
    CREATE INDEX IF NOT EXISTS idx_snapshots_account_time ON balance_snapshots(account_id, checked_at DESC);
    CREATE TRIGGER IF NOT EXISTS retain_recent_failures AFTER INSERT ON balance_history
    WHEN NEW.status = 'error'
    BEGIN
        DELETE FROM balance_history WHERE status = 'error' AND id NOT IN (
            SELECT id FROM balance_history WHERE status = 'error' ORDER BY id DESC LIMIT 20
        );
    END;
    DELETE FROM balance_history WHERE status = 'error' AND id NOT IN (
        SELECT id FROM balance_history WHERE status = 'error' ORDER BY id DESC LIMIT 20
    );
    CREATE TABLE IF NOT EXISTS app_settings (
        key TEXT PRIMARY KEY,
        value_enc TEXT NOT NULL,
        updated_at TEXT NOT NULL
    );
    `
	_, err := db.Exec(schema)
	if err != nil {
		return err
	}
	if err := ensureColumn(db, "accounts", "api_user_id", "TEXT NOT NULL DEFAULT ''"); err != nil {
		return err
	}
	if err := ensureColumn(db, "accounts", "base_provider", "TEXT NOT NULL DEFAULT ''"); err != nil {
		return err
	}
	if _, err := db.Exec(`INSERT INTO balance_snapshots(account_id,balance,checked_at)
        SELECT a.id,a.balance,a.last_checked_at FROM accounts a
        WHERE a.status='ok' AND a.last_checked_at IS NOT NULL
          AND NOT EXISTS (SELECT 1 FROM balance_snapshots s WHERE s.account_id=a.id)`); err != nil {
		return err
	}
	return migrateAccountPlatforms(db)
}

func ensureColumn(db *sql.DB, table, column, definition string) error {
	rows, err := db.Query("PRAGMA table_info(" + table + ")")
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var cid int
		var name, columnType string
		var notNull, primaryKey int
		var defaultValue any
		if err := rows.Scan(&cid, &name, &columnType, &notNull, &defaultValue, &primaryKey); err != nil {
			return err
		}
		if name == column {
			return nil
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	rows.Close()
	_, err = db.Exec("ALTER TABLE " + table + " ADD COLUMN " + column + " " + definition)
	return err
}

func (a *app) handleWeb(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	data, err := webFS.ReadFile("web/index.html")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(data)
}

func withSecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "same-origin")
		next.ServeHTTP(w, r)
	})
}

func withCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "same-origin")
		if r.Method == http.MethodOptions {
			w.Header().Set("Access-Control-Allow-Methods", "GET,POST,PUT,DELETE,OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (a *app) sessionUserID(r *http.Request) (int64, bool) {
	cookie, err := r.Cookie("balancemt_session")
	if err != nil || cookie.Value == "" {
		return 0, false
	}
	var userID int64
	var expires string
	err = a.db.QueryRow(`SELECT user_id, expires_at FROM sessions WHERE token = ?`, cookie.Value).Scan(&userID, &expires)
	if err != nil {
		return 0, false
	}
	t, err := time.Parse(time.RFC3339, expires)
	if err != nil || t.Before(time.Now()) {
		_, _ = a.db.Exec(`DELETE FROM sessions WHERE token = ?`, cookie.Value)
		return 0, false
	}
	return userID, true
}

func (a *app) authenticated(r *http.Request) bool {
	_, ok := a.sessionUserID(r)
	return ok
}

func (a *app) requireAuth(w http.ResponseWriter, r *http.Request) bool {
	if a.authenticated(r) {
		return true
	}
	writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "未登录"})
	return false
}

func (a *app) handleAuthStatus(w http.ResponseWriter, r *http.Request) {
	var count int
	_ = a.db.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&count)
	writeJSON(w, http.StatusOK, map[string]any{
		"setup_required": count == 0,
		"authenticated":  a.authenticated(r),
	})
}

func (a *app) handleSetup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var count int
	_ = a.db.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&count)
	if count > 0 {
		writeJSON(w, http.StatusConflict, map[string]any{"error": "管理员已初始化"})
		return
	}
	var input struct{ Username, Password string }
	if !decodeJSON(w, r, &input) || len(strings.TrimSpace(input.Username)) < 3 || len(input.Password) < 6 {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "用户名至少 3 位，密码至少 6 位"})
		return
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(input.Password), bcrypt.DefaultCost)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "初始化失败"})
		return
	}
	_, err = a.db.Exec(`INSERT INTO users(username, password_hash, created_at) VALUES(?,?,?)`, strings.TrimSpace(input.Username), string(hash), time.Now().UTC().Format(time.RFC3339))
	if err != nil {
		writeJSON(w, http.StatusConflict, map[string]any{"error": "初始化失败"})
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"ok": true})
}

func (a *app) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var input struct{ Username, Password string }
	if !decodeJSON(w, r, &input) {
		return
	}
	var id int64
	var hash string
	err := a.db.QueryRow(`SELECT id, password_hash FROM users WHERE username = ?`, strings.TrimSpace(input.Username)).Scan(&id, &hash)
	if err != nil || bcrypt.CompareHashAndPassword([]byte(hash), []byte(input.Password)) != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "用户名或密码不正确"})
		return
	}
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "登录失败"})
		return
	}
	token := base64.RawURLEncoding.EncodeToString(tokenBytes)
	expires := time.Now().Add(7 * 24 * time.Hour).UTC().Format(time.RFC3339)
	_, _ = a.db.Exec(`INSERT INTO sessions(token,user_id,expires_at) VALUES(?,?,?)`, token, id, expires)
	http.SetCookie(w, &http.Cookie{Name: "balancemt_session", Value: token, Path: "/", HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: 7 * 24 * 3600})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "username": input.Username})
}

func (a *app) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	userID, ok := a.sessionUserID(r)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "未登录"})
		return
	}
	var input struct {
		CurrentPassword string `json:"current_password"`
		NewPassword     string `json:"new_password"`
		ConfirmPassword string `json:"confirm_password"`
	}
	if !decodeJSON(w, r, &input) {
		return
	}
	if len(input.NewPassword) < 6 {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "新密码至少 6 位"})
		return
	}
	if input.NewPassword != input.ConfirmPassword {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "两次输入的新密码不一致"})
		return
	}
	var currentHash string
	if err := a.db.QueryRow(`SELECT password_hash FROM users WHERE id = ?`, userID).Scan(&currentHash); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "用户不存在"})
		return
	}
	if bcrypt.CompareHashAndPassword([]byte(currentHash), []byte(input.CurrentPassword)) != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "原密码不正确"})
		return
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(input.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "修改密码失败"})
		return
	}
	if _, err := a.db.Exec(`UPDATE users SET password_hash = ? WHERE id = ?`, string(hash), userID); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "修改密码失败"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}
func (a *app) handleLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if cookie, err := r.Cookie("balancemt_session"); err == nil {
		_, _ = a.db.Exec(`DELETE FROM sessions WHERE token = ?`, cookie.Value)
	}
	http.SetCookie(w, &http.Cookie{Name: "balancemt_session", Value: "", Path: "/", MaxAge: -1, HttpOnly: true, SameSite: http.SameSiteLaxMode})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (a *app) handleAccounts(w http.ResponseWriter, r *http.Request) {
	if !a.requireAuth(w, r) {
		return
	}
	switch r.Method {
	case http.MethodGet:
		accounts, err := a.listAccounts()
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, accounts)
	case http.MethodPost:
		var input accountInput
		if !decodeJSON(w, r, &input) {
			return
		}
		id, err := a.createAccount(input)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
			return
		}
		go a.checkAndAlert(id)
		writeJSON(w, http.StatusCreated, map[string]any{"id": id})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (a *app) handleAccountAction(w http.ResponseWriter, r *http.Request) {
	if !a.requireAuth(w, r) {
		return
	}
	path := strings.TrimPrefix(r.URL.Path, "/api/accounts/")
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) == 0 || parts[0] == "" {
		http.NotFound(w, r)
		return
	}
	id, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if len(parts) == 2 && parts[1] == "check" && r.Method == http.MethodPost {
		account, err := a.checkAndAlert(id)
		if err != nil {
			writeJSON(w, http.StatusBadGateway, map[string]any{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, account)
		return
	}
	switch r.Method {
	case http.MethodPut:
		var input accountInput
		if !decodeJSON(w, r, &input) {
			return
		}
		if err := a.updateAccount(id, input); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	case http.MethodDelete:
		if _, err := a.db.Exec(`DELETE FROM accounts WHERE id = ?`, id); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (a *app) handleHistory(w http.ResponseWriter, r *http.Request) {
	if !a.requireAuth(w, r) {
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	if r.Method == http.MethodDelete {
		if r.URL.Query().Get("status") != "error" {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "仅支持清空失败记录，请指定 status=error"})
			return
		}
		if _, err := a.db.Exec(`DELETE FROM balance_history WHERE status='error'`); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "清空失败记录失败，请重试"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
		return
	}
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	status := r.URL.Query().Get("status")
	if status != "" && status != "error" && status != "ok" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "记录状态必须为 error 或 ok"})
		return
	}
	query := `SELECT h.account_id, a.name, h.balance, h.status, COALESCE(h.error,''), h.checked_at FROM balance_history h JOIN accounts a ON a.id = h.account_id`
	var args []any
	if status != "" {
		query += " WHERE h.status=?"
		args = append(args, status)
	}
	if status == "error" {
		query += " ORDER BY h.id DESC LIMIT 20"
	} else {
		query += " ORDER BY h.id DESC LIMIT 80"
	}
	rows, err := a.db.Query(query, args...)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "读取检查记录失败"})
		return
	}
	defer rows.Close()
	type item struct {
		AccountID int64   `json:"account_id"`
		Name      string  `json:"name"`
		Balance   float64 `json:"balance"`
		Status    string  `json:"status"`
		Error     string  `json:"error,omitempty"`
		CheckedAt string  `json:"checked_at"`
	}
	out := make([]item, 0)
	for rows.Next() {
		var v item
		if err := rows.Scan(&v.AccountID, &v.Name, &v.Balance, &v.Status, &v.Error, &v.CheckedAt); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "读取检查记录失败"})
			return
		}
		out = append(out, v)
	}
	if err := rows.Err(); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "读取检查记录失败"})
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, out)
}

type storedAlertSettings struct {
	MonitorIntervalSeconds int         `json:"monitor_interval_seconds"`
	UsageWindowHours       int         `json:"usage_window_hours,omitempty"`
	Alerts                 alertConfig `json:"alerts"`
}

func (a *app) handleAlertSettings(w http.ResponseWriter, r *http.Request) {
	if !a.requireAuth(w, r) {
		return
	}
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, a.alertSettingsResponse())
	case http.MethodPut:
		var input alertSettingsInput
		if !decodeJSON(w, r, &input) {
			return
		}
		if err := a.updateAlertSettings(input); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, a.alertSettingsResponse())
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (a *app) handleAlertSettingsTest(w http.ResponseWriter, r *http.Request) {
	if !a.requireAuth(w, r) {
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var input alertSettingsInput
	if !decodeJSON(w, r, &input) {
		return
	}
	cfg, _, err := a.mergeAlertSettings(input)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	var errorsFound []string
	if cfg.emailEnabled() {
		if err := sendEmailWithConfig(cfg, "BalanceMT test alert", "This is a test alert from BalanceMT."); err != nil {
			errorsFound = append(errorsFound, "邮件: "+err.Error())
		}
	}
	if cfg.smsEnabled() {
		if err := a.sendSMSWithConfig(cfg, "BalanceMT test alert"); err != nil {
			errorsFound = append(errorsFound, "短信: "+err.Error())
		}
	}
	if !cfg.emailEnabled() && !cfg.smsEnabled() {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "请至少配置一个可用的告警通道"})
		return
	}
	if len(errorsFound) > 0 {
		writeJSON(w, http.StatusBadGateway, map[string]any{"error": strings.Join(errorsFound, "; ")})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "message": "测试告警已发送"})
}

func (a *app) alertSettingsResponse() alertSettingsResponse {
	cfg := a.currentAlertConfig()
	interval := int(a.currentMonitorInterval() / time.Second)
	if interval < 1 {
		interval = 10
	}
	return alertSettingsResponse{
		MonitorIntervalSeconds:    interval,
		UsageWindowHours:          a.currentUsageWindowHours(),
		SMTPHost:                  cfg.SMTPHost,
		SMTPPort:                  cfg.SMTPPort,
		SMTPUsername:              cfg.SMTPUsername,
		SMTPFrom:                  cfg.SMTPFrom,
		AlertEmailTo:              strings.Join(cfg.EmailTo, ", "),
		EmailConfigured:           cfg.emailEnabled(),
		SMTPPasswordConfigured:    cfg.SMTPPassword != "",
		SMSProvider:               cfg.SMSProvider,
		SMSTo:                     cfg.SMSTo,
		SMSWebhookURL:             cfg.SMSWebhookURL,
		SMSWebhookConfigured:      cfg.SMSWebhookURL != "",
		SMSWebhookTokenConfigured: cfg.SMSWebhookToken != "",
		TwilioAccountSID:          cfg.TwilioAccountSID,
		TwilioFrom:                cfg.TwilioFrom,
		TwilioConfigured:          cfg.TwilioAccountSID != "" && cfg.TwilioAuthToken != "" && cfg.TwilioFrom != "",
		TwilioAuthTokenConfigured: cfg.TwilioAuthToken != "",
	}
}

func (a *app) updateAlertSettings(input alertSettingsInput) error {
	a.settingsMu.Lock()
	defer a.settingsMu.Unlock()
	cfg, interval, err := a.mergeAlertSettings(input)
	if err != nil {
		return err
	}
	usageWindow := input.UsageWindowHours
	if usageWindow == 0 {
		usageWindow = a.currentUsageWindowHours()
	}
	if usageWindow < 1 || usageWindow > 720 {
		return errors.New("统计窗口必须在 1 到 720 小时之间")
	}
	stored := storedAlertSettings{MonitorIntervalSeconds: interval, UsageWindowHours: usageWindow, Alerts: cfg}
	encrypted, err := a.encrypt(stored)
	if err != nil {
		return err
	}
	now := time.Now().UTC().Format(time.RFC3339)
	if _, err := a.db.Exec(`INSERT INTO app_settings(key,value_enc,updated_at) VALUES(?,?,?) ON CONFLICT(key) DO UPDATE SET value_enc=excluded.value_enc,updated_at=excluded.updated_at`, "alerts", encrypted, now); err != nil {
		return err
	}
	a.configMu.Lock()
	oldInterval := a.monitorInterval
	a.alerts = cfg
	a.monitorInterval = time.Duration(interval) * time.Second
	a.usageWindowHours = usageWindow
	a.configMu.Unlock()
	if oldInterval != time.Duration(interval)*time.Second {
		select {
		case a.intervalWake <- struct{}{}:
		default:
		}
	}
	return nil
}

func (a *app) mergeAlertSettings(input alertSettingsInput) (alertConfig, int, error) {
	cfg := a.currentAlertConfig()
	interval := int(a.currentMonitorInterval() / time.Second)
	if input.MonitorIntervalSeconds != 0 {
		interval = input.MonitorIntervalSeconds
	}
	if interval < 1 || interval > 86400 {
		return alertConfig{}, 0, errors.New("检查间隔必须在 1 到 86400 秒之间")
	}
	// Ordinary fields come from the full settings form, so empty values must be
	// allowed to disable or clear a previously configured alert channel.
	cfg.SMTPHost = strings.TrimSpace(input.SMTPHost)
	if input.SMTPPort != 0 {
		cfg.SMTPPort = input.SMTPPort
	}
	if cfg.SMTPPort < 1 || cfg.SMTPPort > 65535 {
		return alertConfig{}, 0, errors.New("SMTP 端口无效")
	}
	cfg.SMTPUsername = strings.TrimSpace(input.SMTPUsername)
	if input.SMTPPassword != "" {
		cfg.SMTPPassword = input.SMTPPassword
	}
	if input.ClearSMTPPassword {
		cfg.SMTPPassword = ""
	}
	cfg.SMTPFrom = strings.TrimSpace(input.SMTPFrom)
	cfg.EmailTo = splitRecipients(input.AlertEmailTo)
	cfg.SMSProvider = strings.ToLower(strings.TrimSpace(input.SMSProvider))
	if cfg.SMSProvider != "" && cfg.SMSProvider != "twilio" && cfg.SMSProvider != "webhook" {
		return alertConfig{}, 0, errors.New("短信服务商必须是 twilio 或 webhook")
	}
	cfg.SMSTo = strings.TrimSpace(input.SMSTo)
	cfg.SMSWebhookURL = strings.TrimSpace(input.SMSWebhookURL)
	if input.SMSWebhookToken != "" {
		cfg.SMSWebhookToken = input.SMSWebhookToken
	}
	if input.ClearSMSWebhookToken {
		cfg.SMSWebhookToken = ""
	}
	cfg.TwilioAccountSID = strings.TrimSpace(input.TwilioAccountSID)
	if input.TwilioAuthToken != "" {
		cfg.TwilioAuthToken = input.TwilioAuthToken
	}
	if input.ClearTwilioAuthToken {
		cfg.TwilioAuthToken = ""
	}
	cfg.TwilioFrom = strings.TrimSpace(input.TwilioFrom)
	return cfg, interval, nil
}

func (a *app) loadStoredAlertSettings() error {
	var encrypted string
	err := a.db.QueryRow(`SELECT value_enc FROM app_settings WHERE key=?`, "alerts").Scan(&encrypted)
	if err == sql.ErrNoRows {
		return nil
	}
	if err != nil {
		return err
	}
	raw, err := a.decrypt(encrypted)
	if err != nil {
		return err
	}
	var stored storedAlertSettings
	if err := json.Unmarshal(raw, &stored); err != nil {
		return err
	}
	if stored.MonitorIntervalSeconds < 1 || stored.MonitorIntervalSeconds > 86400 {
		return errors.New("stored monitor interval is invalid")
	}
	usageWindow := stored.UsageWindowHours
	if usageWindow == 0 {
		usageWindow = 24
	}
	if usageWindow < 1 || usageWindow > 720 {
		return errors.New("stored usage window is invalid")
	}
	a.configMu.Lock()
	a.alerts = stored.Alerts
	a.monitorInterval = time.Duration(stored.MonitorIntervalSeconds) * time.Second
	a.usageWindowHours = usageWindow
	a.configMu.Unlock()
	return nil
}

func (a *app) currentAlertConfig() alertConfig {
	a.configMu.RLock()
	defer a.configMu.RUnlock()
	return a.alerts
}

func (a *app) currentMonitorInterval() time.Duration {
	a.configMu.RLock()
	defer a.configMu.RUnlock()
	return a.monitorInterval
}

func (a *app) currentUsageWindowHours() int {
	a.configMu.RLock()
	defer a.configMu.RUnlock()
	if a.usageWindowHours < 1 {
		return 24
	}
	return a.usageWindowHours
}

func (a *app) listAccounts() ([]Account, error) {
	rows, err := a.db.Query(`SELECT id,name,provider,base_provider,base_url,identifier,COALESCE(api_user_id,''),currency,threshold,enabled,balance,COALESCE(last_checked_at,''),status,COALESCE(last_error,''),COALESCE(login_path,''),COALESCE(balance_path,''),COALESCE(identifier_key,''),COALESCE(token_field,''),COALESCE(balance_field,''),balance_scale,created_at FROM accounts ORDER BY id DESC`)
	if err != nil {
		return nil, err
	}
	out := make([]Account, 0)
	for rows.Next() {
		var v Account
		var enabled int
		if err := rows.Scan(&v.ID, &v.Name, &v.Provider, &v.BaseProvider, &v.BaseURL, &v.Identifier, &v.APIUserID, &v.Currency, &v.Threshold, &enabled, &v.Balance, &v.LastCheckedAt, &v.Status, &v.Error, &v.LoginPath, &v.BalancePath, &v.IdentifierKey, &v.TokenField, &v.BalanceField, &v.BalanceScale, &v.CreatedAt); err != nil {
			rows.Close()
			return nil, err
		}
		v.Enabled = enabled == 1
		out = append(out, v)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	rows.Close()
	windowHours := a.currentUsageWindowHours()
	now := time.Now().UTC()
	for i := range out {
		usage, err := a.accountUsage(out[i].ID, out[i].Balance, now, windowHours)
		if err != nil {
			return nil, err
		}
		out[i].UsageWindowHours = windowHours
		out[i].Consumption = usage.Consumption
		out[i].EstimatedHours = usage.EstimatedHours
		out[i].UsageSamples = usage.Samples
		out[i].UsageReady = usage.Ready
	}
	return out, nil
}

func (a *app) accountUsage(accountID int64, currentBalance float64, now time.Time, windowHours int) (balanceUsage, error) {
	if windowHours < 1 {
		windowHours = 24
	}
	cutoff := now.Add(-time.Duration(windowHours) * time.Hour)
	type sample struct {
		balance   float64
		checkedAt time.Time
	}
	samples := make([]sample, 0, 8)
	var baselineBalance float64
	var baselineAt string
	err := a.db.QueryRow(`SELECT balance,checked_at FROM balance_snapshots WHERE account_id=? AND checked_at<=? ORDER BY checked_at DESC,id DESC LIMIT 1`, accountID, cutoff.Format(time.RFC3339)).Scan(&baselineBalance, &baselineAt)
	if err == nil {
		parsed, parseErr := time.Parse(time.RFC3339, baselineAt)
		if parseErr != nil {
			return balanceUsage{}, parseErr
		}
		samples = append(samples, sample{baselineBalance, parsed})
	} else if err != sql.ErrNoRows {
		return balanceUsage{}, err
	}
	rows, err := a.db.Query(`SELECT balance,checked_at FROM balance_snapshots WHERE account_id=? AND checked_at>? ORDER BY checked_at ASC,id ASC`, accountID, cutoff.Format(time.RFC3339))
	if err != nil {
		return balanceUsage{}, err
	}
	defer rows.Close()
	for rows.Next() {
		var balance float64
		var checkedAt string
		if err := rows.Scan(&balance, &checkedAt); err != nil {
			return balanceUsage{}, err
		}
		parsed, err := time.Parse(time.RFC3339, checkedAt)
		if err != nil {
			return balanceUsage{}, err
		}
		samples = append(samples, sample{balance, parsed})
	}
	if err := rows.Err(); err != nil {
		return balanceUsage{}, err
	}
	usage := balanceUsage{Samples: len(samples)}
	if len(samples) < 2 {
		return usage, nil
	}
	start := samples[0].checkedAt
	if start.Before(cutoff) {
		start = cutoff
	}
	end := samples[len(samples)-1].checkedAt
	elapsed := end.Sub(start).Hours()
	if elapsed <= 0 {
		return usage, nil
	}
	for i := 1; i < len(samples); i++ {
		drop := samples[i-1].balance - samples[i].balance
		if drop > 0 {
			usage.Consumption += drop
		}
	}
	usage.Ready = true
	if usage.Consumption > 1e-9 {
		usage.EstimatedHours = currentBalance / (usage.Consumption / elapsed)
		if usage.EstimatedHours < 0 {
			usage.EstimatedHours = 0
		}
	}
	return usage, nil
}

func (a *app) createAccount(input accountInput) (int64, error) {
	normalizeAccountInput(&input)
	if err := validateAccountPlatform(input); err != nil {
		return 0, err
	}
	if input.Name == "" || input.BaseURL == "" || input.Identifier == "" {
		return 0, errors.New("名称、地址和账号不能为空")
	}
	if strings.TrimSpace(input.Password) == "" && strings.TrimSpace(input.AccessToken) == "" {
		return 0, errors.New("密码和访问令牌至少填写一个")
	}
	encrypted, err := a.encrypt(accountSecret{Identifier: input.Identifier, Password: input.Password, AccessToken: strings.TrimSpace(input.AccessToken)})
	if err != nil {
		return 0, err
	}
	enabled := 1
	if input.Enabled != nil && !*input.Enabled {
		enabled = 0
	}
	now := time.Now().UTC().Format(time.RFC3339)
	result, err := a.db.Exec(`INSERT INTO accounts(name,provider,base_provider,base_url,identifier,api_user_id,secret_enc,currency,threshold,enabled,login_path,balance_path,identifier_key,token_field,balance_field,balance_scale,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, input.Name, input.Provider, input.BaseProvider, strings.TrimRight(input.BaseURL, "/"), input.Identifier, input.APIUserID, encrypted, input.Currency, input.Threshold, enabled, input.LoginPath, input.BalancePath, input.IdentifierKey, input.TokenField, input.BalanceField, input.BalanceScale, now, now)
	if err != nil {
		return 0, err
	}
	return result.LastInsertId()
}

func (a *app) updateAccount(id int64, input accountInput) error {
	normalizeAccountInput(&input)
	if err := validateAccountPlatform(input); err != nil {
		return err
	}
	if input.Name == "" || input.BaseURL == "" {
		return errors.New("名称和地址不能为空")
	}

	var current string
	if err := a.db.QueryRow(`SELECT secret_enc FROM accounts WHERE id=?`, id).Scan(&current); err != nil {
		return err
	}

	var old accountSecret
	raw, err := a.decrypt(current)
	if err != nil {
		return fmt.Errorf("无法解密原账户凭据: %w", err)
	}
	if err := json.Unmarshal(raw, &old); err != nil {
		return fmt.Errorf("原账户凭据格式无效: %w", err)
	}
	if input.Identifier == "" {
		input.Identifier = old.Identifier
	}
	if input.Identifier == "" {
		return errors.New("登录账号不能为空")
	}

	password := input.Password
	if password == "" {
		password = old.Password
	}
	accessToken := strings.TrimSpace(input.AccessToken)
	if accessToken == "" && strings.TrimSpace(input.Password) == "" {
		accessToken = old.AccessToken
	}
	if strings.TrimSpace(password) == "" && accessToken == "" {
		return errors.New("密码和访问令牌至少保留一个")
	}
	encrypted, err := a.encrypt(accountSecret{Identifier: input.Identifier, Password: password, AccessToken: accessToken})
	if err != nil {
		return err
	}

	enabled := 1
	if input.Enabled != nil && !*input.Enabled {
		enabled = 0
	}
	_, err = a.db.Exec(`UPDATE accounts SET name=?,provider=?,base_provider=?,base_url=?,identifier=?,api_user_id=?,secret_enc=?,currency=?,threshold=?,enabled=?,login_path=?,balance_path=?,identifier_key=?,token_field=?,balance_field=?,balance_scale=?,updated_at=? WHERE id=?`, input.Name, input.Provider, input.BaseProvider, strings.TrimRight(input.BaseURL, "/"), input.Identifier, input.APIUserID, encrypted, input.Currency, input.Threshold, enabled, input.LoginPath, input.BalancePath, input.IdentifierKey, input.TokenField, input.BalanceField, input.BalanceScale, time.Now().UTC().Format(time.RFC3339), id)
	return err
}
func normalizeAccountInput(input *accountInput) {
	normalizeAccountPlatform(input)
	if input.Currency == "" {
		input.Currency = "USD"
	}
	input.Name = strings.TrimSpace(input.Name)
	input.BaseURL = strings.TrimSpace(input.BaseURL)
	input.Identifier = strings.TrimSpace(input.Identifier)
	input.APIUserID = strings.TrimSpace(input.APIUserID)
}

func (a *app) checkAccount(id int64) (Account, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	var v Account
	var secretEnc string
	var enabled int
	err := a.db.QueryRow(`SELECT id,name,provider,base_provider,base_url,identifier,COALESCE(api_user_id,''),currency,threshold,enabled,balance,COALESCE(last_checked_at,''),status,COALESCE(last_error,''),COALESCE(login_path,''),COALESCE(balance_path,''),COALESCE(identifier_key,''),COALESCE(token_field,''),COALESCE(balance_field,''),balance_scale,created_at,secret_enc FROM accounts WHERE id=?`, id).Scan(&v.ID, &v.Name, &v.Provider, &v.BaseProvider, &v.BaseURL, &v.Identifier, &v.APIUserID, &v.Currency, &v.Threshold, &enabled, &v.Balance, &v.LastCheckedAt, &v.Status, &v.Error, &v.LoginPath, &v.BalancePath, &v.IdentifierKey, &v.TokenField, &v.BalanceField, &v.BalanceScale, &v.CreatedAt, &secretEnc)
	if err != nil {
		return v, err
	}
	v.Enabled = enabled == 1
	raw, err := a.decrypt(secretEnc)
	if err != nil {
		return a.updateCheckState(v, "error", err)
	}
	var secret accountSecret
	if err := json.Unmarshal(raw, &secret); err != nil {
		return a.updateCheckState(v, "error", err)
	}
	result, err := a.fetchBalance(v, secret)
	now := time.Now().UTC().Format(time.RFC3339)
	if err != nil {
		return a.updateCheckState(v, "error", err)
	}
	v.Balance = result.Balance
	v.Status = "ok"
	v.Error = ""
	v.LastCheckedAt = now
	if _, err := a.db.Exec(`UPDATE accounts SET balance=?,status='ok',last_error=NULL,last_checked_at=?,updated_at=? WHERE id=?`, v.Balance, now, now, id); err != nil {
		log.Printf("account %d: save success state: %v", id, err)
	}
	if err := a.recordBalanceSnapshot(id, v.Balance, now); err != nil {
		log.Printf("account %d: save balance snapshot: %v", id, err)
	}
	return v, nil
}

func (a *app) recordBalanceSnapshot(accountID int64, balance float64, checkedAt string) error {
	var previous float64
	var previousAt string
	err := a.db.QueryRow(`SELECT balance,checked_at FROM balance_snapshots WHERE account_id=? ORDER BY checked_at DESC,id DESC LIMIT 1`, accountID).Scan(&previous, &previousAt)
	if err != nil && err != sql.ErrNoRows {
		return err
	}
	if err == nil {
		last, parseErr := time.Parse(time.RFC3339, previousAt)
		if parseErr != nil {
			return parseErr
		}
		current, parseErr := time.Parse(time.RFC3339, checkedAt)
		if parseErr != nil {
			return parseErr
		}
		if math.Abs(previous-balance) <= 1e-9 && current.Sub(last) < 5*time.Minute {
			return nil
		}
	}
	_, err = a.db.Exec(`INSERT INTO balance_snapshots(account_id,balance,checked_at) VALUES(?,?,?)`, accountID, balance, checkedAt)
	return err
}

func (a *app) updateCheckState(v Account, status string, err error) (Account, error) {
	message := err.Error()
	now := time.Now().UTC().Format(time.RFC3339)
	v.Status, v.Error, v.LastCheckedAt = status, message, now
	if _, dbErr := a.db.Exec(`UPDATE accounts SET status=?,last_error=?,last_checked_at=?,updated_at=? WHERE id=?`, status, message, now, now, v.ID); dbErr != nil {
		log.Printf("account %d: save error state: %v", v.ID, dbErr)
	}
	if _, dbErr := a.db.Exec(`INSERT INTO balance_history(account_id,balance,status,error,checked_at) VALUES(?,?,?,?,?)`, v.ID, v.Balance, status, message, now); dbErr != nil {
		log.Printf("account %d: save error history: %v", v.ID, dbErr)
	}
	return v, err
}

func (a *app) fetchBalance(account Account, secret accountSecret) (balanceResult, error) {
	token := strings.TrimSpace(secret.AccessToken)
	apiUserID := strings.TrimSpace(account.APIUserID)
	if token == "" {
		loginURL := strings.TrimRight(account.BaseURL, "/") + ensurePath(account.LoginPath)
		payload := map[string]string{account.IdentifierKey: secret.Identifier, "password": secret.Password}
		loginBody, status, err := a.requestJSON(http.MethodPost, loginURL, "", payload)
		if err != nil {
			return balanceResult{}, fmt.Errorf("登录接口: %w", err)
		}
		if status < 200 || status >= 300 {
			return balanceResult{}, responseStatusError("登录接口", status, loginBody)
		}
		token, _ = lookupString(loginBody, account.TokenField)
		if token == "" {
			if message, ok := lookupString(loginBody, "message"); ok && strings.TrimSpace(message) != "" {
				return balanceResult{}, fmt.Errorf("登录失败: %s", message)
			}
			return balanceResult{}, fmt.Errorf("登录接口未返回 access token，期望字段 %q", account.TokenField)
		}
		if apiUserID == "" {
			if id, ok := lookupNumber(loginBody, "data.id"); ok {
				apiUserID = strconv.FormatInt(int64(id), 10)
			}
		}
	}
	token = strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(token, "Bearer "), "bearer "))
	balanceURL := strings.TrimRight(account.BaseURL, "/") + ensurePath(account.BalancePath)
	headers := map[string]string{}
	if apiUserID != "" {
		headers["New-Api-User"] = apiUserID
	}
	body, status, err := a.requestJSONWithHeaders(http.MethodGet, balanceURL, token, nil, headers)
	if err != nil {
		return balanceResult{}, fmt.Errorf("余额接口: %w", err)
	}
	if status < 200 || status >= 300 {
		return balanceResult{}, responseStatusError("余额接口", status, body)
	}
	raw, ok := lookupNumber(body, account.BalanceField)
	if !ok {
		for _, field := range []string{"data.balance", "data.quota", "balance", "quota"} {
			if raw, ok = lookupNumber(body, field); ok {
				break
			}
		}
	}
	if !ok {
		return balanceResult{}, fmt.Errorf("响应中未找到余额字段 %q", account.BalanceField)
	}
	scale := account.BalanceScale
	if scale == 0 {
		scale = 1
	}
	return balanceResult{Balance: raw / scale, Raw: raw}, nil
}

func responseStatusError(stage string, status int, body map[string]any) error {
	if message, ok := lookupString(body, "message"); ok && strings.TrimSpace(message) != "" {
		return fmt.Errorf("%s返回 HTTP %d: %s", stage, status, message)
	}
	return fmt.Errorf("%s返回 HTTP %d", stage, status)
}

func (a *app) requestJSON(method, url, token string, payload any) (map[string]any, int, error) {
	return a.requestJSONWithHeaders(method, url, token, payload, nil)
}

func (a *app) requestJSONWithHeaders(method, url, token string, payload any, extraHeaders map[string]string) (map[string]any, int, error) {
	var body io.Reader
	if payload != nil {
		data, err := json.Marshal(payload)
		if err != nil {
			return nil, 0, err
		}
		body = strings.NewReader(string(data))
	}
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Accept", "application/json")
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	for key, value := range extraHeaders {
		if strings.TrimSpace(value) != "" {
			req.Header.Set(key, value)
		}
	}
	resp, err := a.httpClient.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("请求失败: %w", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if err != nil {
		return nil, resp.StatusCode, err
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		contentType := resp.Header.Get("Content-Type")
		return nil, resp.StatusCode, fmt.Errorf("接口返回不是 JSON (HTTP %d, Content-Type %q, 响应: %q)", resp.StatusCode, contentType, summarizeResponse(raw))
	}
	return out, resp.StatusCode, nil
}

func summarizeResponse(raw []byte) string {
	text := strings.Join(strings.Fields(string(raw)), " ")
	const max = 240
	if len(text) > max {
		return text[:max] + "..."
	}
	return text
}

func (a *app) monitorLoop() {
	a.runMonitorPass()
	timer := time.NewTimer(a.currentMonitorInterval())
	defer timer.Stop()
	for {
		select {
		case <-timer.C:
			a.runMonitorPass()
			timer.Reset(a.currentMonitorInterval())
		case <-a.intervalWake:
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			timer.Reset(a.currentMonitorInterval())
		}
	}
}

func (a *app) runMonitorPass() {
	var ids []int64
	rows, err := a.db.Query(`SELECT id FROM accounts WHERE enabled=1`)
	if err != nil {
		log.Printf("load monitor accounts: %v", err)
		return
	}
	for rows.Next() {
		var id int64
		if rows.Scan(&id) == nil {
			ids = append(ids, id)
		}
	}
	rows.Close()
	for _, id := range ids {
		_, _ = a.checkAndAlert(id)
	}
}

func (a *app) checkAndAlert(id int64) (Account, error) {
	account, err := a.checkAccount(id)
	if account.ID != 0 {
		a.maybeAlert(account)
	}
	return account, err
}

func (a *app) maybeAlert(account Account) {
	low := account.Status == "ok" && account.Threshold > 0 && account.Balance <= account.Threshold
	failed := account.Status == "error"

	a.alertMu.Lock()
	previous := a.alertStates[account.ID]
	next := alertState{lowBalance: low, checkError: failed}
	shouldLow := low && !previous.lowBalance
	shouldError := failed && !previous.checkError
	a.alertStates[account.ID] = next
	a.alertMu.Unlock()

	if shouldLow {
		go a.sendAlert(account, "余额低于阈值", fmt.Sprintf("当前余额 %.4f %s，提醒阈值 %.4f %s。", account.Balance, account.Currency, account.Threshold, account.Currency))
	}
	if shouldError {
		go a.sendAlert(account, "余额检查失败", account.Error)
	}
}

func (a *app) sendAlert(account Account, subject, detail string) {
	title := fmt.Sprintf("BalanceMT alert #%d", account.ID)
	body := fmt.Sprintf("BalanceMT 告警\n站点: %s\n平台: %s\n时间: %s\n原因: %s\n", account.Name, account.Provider, time.Now().Format(time.RFC3339), detail)
	cfg := a.currentAlertConfig()
	var errs []string
	if cfg.emailEnabled() {
		if err := sendEmailWithConfig(cfg, title, body); err != nil {
			errs = append(errs, "email: "+err.Error())
		}
	}
	if cfg.smsEnabled() {
		if err := a.sendSMSWithConfig(cfg, title+" - "+detail); err != nil {
			errs = append(errs, "sms: "+err.Error())
		}
	}
	if len(errs) > 0 {
		log.Printf("account %d alert failed: %s", account.ID, strings.Join(errs, "; "))
	}
}

func (c alertConfig) emailEnabled() bool {
	return c.SMTPHost != "" && c.SMTPFrom != "" && len(c.EmailTo) > 0
}

func (c alertConfig) smsEnabled() bool {
	return c.SMSTo != "" && ((c.SMSProvider == "twilio" && c.TwilioAccountSID != "" && c.TwilioAuthToken != "" && c.TwilioFrom != "") || (c.SMSProvider == "webhook" && c.SMSWebhookURL != ""))
}

func sendEmailWithConfig(cfg alertConfig, subject, body string) error {
	port := cfg.SMTPPort
	if port == 0 {
		port = 587
	}
	recipients := cfg.EmailTo
	message := "From: " + cfg.SMTPFrom + "\r\n" +
		"To: " + strings.Join(recipients, ", ") + "\r\n" +
		"Subject: " + subject + "\r\n" +
		"Content-Type: text/plain; charset=UTF-8\r\n\r\n" + body
	addr := net.JoinHostPort(cfg.SMTPHost, strconv.Itoa(port))
	var auth smtp.Auth
	if cfg.SMTPUsername != "" {
		auth = smtp.PlainAuth("", cfg.SMTPUsername, cfg.SMTPPassword, cfg.SMTPHost)
	}
	if port != 465 {
		return smtp.SendMail(addr, auth, cfg.SMTPFrom, recipients, []byte(message))
	}

	conn, err := tls.Dial("tcp", addr, &tls.Config{ServerName: cfg.SMTPHost, MinVersion: tls.VersionTLS12})
	if err != nil {
		return err
	}
	client, err := smtp.NewClient(conn, cfg.SMTPHost)
	if err != nil {
		return err
	}
	defer client.Close()
	if auth != nil {
		if err := client.Auth(auth); err != nil {
			return err
		}
	}
	if err := client.Mail(cfg.SMTPFrom); err != nil {
		return err
	}
	for _, recipient := range recipients {
		if err := client.Rcpt(recipient); err != nil {
			return err
		}
	}
	writer, err := client.Data()
	if err != nil {
		return err
	}
	if _, err := writer.Write([]byte(message)); err != nil {
		_ = writer.Close()
		return err
	}
	if err := writer.Close(); err != nil {
		return err
	}
	return client.Quit()
}

func (a *app) sendSMSWithConfig(cfg alertConfig, message string) error {
	switch cfg.SMSProvider {
	case "twilio":
		endpoint := "https://api.twilio.com/2010-04-01/Accounts/" + url.PathEscape(cfg.TwilioAccountSID) + "/Messages.json"
		form := url.Values{"To": {cfg.SMSTo}, "From": {cfg.TwilioFrom}, "Body": {message}}
		req, err := http.NewRequest(http.MethodPost, endpoint, strings.NewReader(form.Encode()))
		if err != nil {
			return err
		}
		req.SetBasicAuth(cfg.TwilioAccountSID, cfg.TwilioAuthToken)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		return a.checkNotificationResponse(req)
	case "webhook":
		payload, _ := json.Marshal(map[string]string{"to": cfg.SMSTo, "message": message})
		req, err := http.NewRequest(http.MethodPost, cfg.SMSWebhookURL, strings.NewReader(string(payload)))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/json")
		if cfg.SMSWebhookToken != "" {
			req.Header.Set("Authorization", "Bearer "+cfg.SMSWebhookToken)
		}
		return a.checkNotificationResponse(req)
	default:
		return errors.New("SMS_PROVIDER must be twilio or webhook")
	}
}

func (a *app) checkNotificationResponse(req *http.Request) error {
	resp, err := a.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, summarizeResponse(raw))
	}
	return nil
}

func loadMonitorInterval() time.Duration {
	if value, ok := os.LookupEnv("MONITOR_INTERVAL_SECONDS"); ok {
		if seconds, err := strconv.Atoi(value); err == nil && seconds > 0 {
			if seconds > 86400 {
				seconds = 86400
			}
			return time.Duration(seconds) * time.Second
		}
	}
	if value, ok := os.LookupEnv("MONITOR_INTERVAL_MINUTES"); ok {
		if minutes, err := strconv.Atoi(value); err == nil && minutes > 0 {
			return time.Duration(minutes) * time.Minute
		}
	}
	return 10 * time.Second
}

func loadAlertConfig() alertConfig {
	port, _ := strconv.Atoi(getenv("SMTP_PORT", "587"))
	return alertConfig{
		SMTPHost:         strings.TrimSpace(os.Getenv("SMTP_HOST")),
		SMTPPort:         port,
		SMTPUsername:     os.Getenv("SMTP_USERNAME"),
		SMTPPassword:     os.Getenv("SMTP_PASSWORD"),
		SMTPFrom:         strings.TrimSpace(os.Getenv("SMTP_FROM")),
		EmailTo:          splitRecipients(os.Getenv("ALERT_EMAIL_TO")),
		SMSProvider:      strings.ToLower(strings.TrimSpace(os.Getenv("SMS_PROVIDER"))),
		SMSTo:            strings.TrimSpace(os.Getenv("SMS_TO")),
		SMSWebhookURL:    strings.TrimSpace(os.Getenv("SMS_WEBHOOK_URL")),
		SMSWebhookToken:  os.Getenv("SMS_WEBHOOK_TOKEN"),
		TwilioAccountSID: strings.TrimSpace(os.Getenv("TWILIO_ACCOUNT_SID")),
		TwilioAuthToken:  os.Getenv("TWILIO_AUTH_TOKEN"),
		TwilioFrom:       strings.TrimSpace(os.Getenv("TWILIO_FROM")),
	}
}

func splitRecipients(value string) []string {
	parts := strings.FieldsFunc(value, func(r rune) bool { return r == ',' || r == ';' || r == ' ' || r == '\n' || r == '\r' })
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		if strings.TrimSpace(part) != "" {
			out = append(out, strings.TrimSpace(part))
		}
	}
	return out
}

func (a *app) encrypt(value any) (string, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(a.key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	sealed := gcm.Seal(nonce, nonce, raw, nil)
	return base64.RawURLEncoding.EncodeToString(sealed), nil
}

func (a *app) decrypt(value string) ([]byte, error) {
	sealed, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(a.key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(sealed) < gcm.NonceSize() {
		return nil, errors.New("密文格式无效")
	}
	return gcm.Open(nil, sealed[:gcm.NonceSize()], sealed[gcm.NonceSize():], nil)
}

func lookupString(value map[string]any, path string) (string, bool) {
	v, ok := lookup(value, path)
	if !ok {
		return "", false
	}
	s, ok := v.(string)
	return s, ok
}

func lookupNumber(value map[string]any, path string) (float64, bool) {
	v, ok := lookup(value, path)
	if !ok {
		return 0, false
	}
	switch n := v.(type) {
	case float64:
		return n, !math.IsNaN(n)
	case json.Number:
		f, err := n.Float64()
		return f, err == nil
	case string:
		f, err := strconv.ParseFloat(strings.TrimSpace(n), 64)
		return f, err == nil
	case int:
		return float64(n), true
	}
	return 0, false
}

func lookup(value map[string]any, path string) (any, bool) {
	if path == "" {
		return nil, false
	}
	var current any = value
	for _, part := range strings.Split(path, ".") {
		object, ok := current.(map[string]any)
		if !ok {
			return nil, false
		}
		current, ok = object[part]
		if !ok {
			return nil, false
		}
	}
	return current, true
}

func ensurePath(path string) string {
	if path == "" {
		return "/"
	}
	if strings.HasPrefix(path, "/") {
		return path
	}
	return "/" + path
}
func getenv(key, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		return value
	}
	return fallback
}

func decodeJSON(w http.ResponseWriter, r *http.Request, dst any) bool {
	defer r.Body.Close()
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(dst); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "请求格式不正确"})
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
