package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	backupFormat    = "balancemt-backup"
	backupVersion   = 3
	backupAlgorithm = "aes-256-gcm"
	backupKeyID     = "balancemt-project-v1"
	backupAAD       = "balancemt-backup:v3:aes-256-gcm:balancemt-project-v1"
	// Keep this project key stable across local/server builds so exported files
	// remain portable. It is bundled with the server, not a user-held secret.
	// Source/binary access permits recovery; database encryption is independent.
	backupProjectKeyHex = "b552f6810a1aa1ae599ef2e2fc6b13aec69139b13f3cbc473871066377348925"
	maxBackupBytes      = 8 << 20
)

// Only the encrypted envelope is sent to the browser. The project key enables
// automatic decryption on other deployments built from this project.
type encryptedBackup struct {
	Format     string `json:"format"`
	Version    int    `json:"version"`
	Algorithm  string `json:"algorithm"`
	KeyID      string `json:"key_id"`
	Nonce      []byte `json:"nonce"`
	Ciphertext []byte `json:"ciphertext"`
}

type backupPayload struct {
	Version    int                 `json:"version"`
	ExportedAt string              `json:"exported_at"`
	Accounts   []accountInput      `json:"accounts"`
	Settings   storedAlertSettings `json:"settings"`
}

type backupImportInput struct {
	Backup       json.RawMessage `json:"backup"`
	Mode         string          `json:"mode"`
	ImportAlerts bool            `json:"import_alerts"`
}

type backupImportResult struct {
	Added          int  `json:"added"`
	Updated        int  `json:"updated"`
	Skipped        int  `json:"skipped"`
	AlertsImported bool `json:"alerts_imported"`
}

func backupCipher() (cipher.AEAD, error) {
	key, err := hex.DecodeString(backupProjectKeyHex)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func sealBackup(payload backupPayload) (encryptedBackup, error) {
	var out encryptedBackup
	raw, err := json.Marshal(payload)
	if err != nil {
		return out, err
	}
	if len(raw) > maxBackupBytes/2 {
		return out, errors.New("配置过大，无法导出")
	}
	gcm, err := backupCipher()
	if err != nil {
		return out, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return out, err
	}
	return encryptedBackup{Format: backupFormat, Version: backupVersion, Algorithm: backupAlgorithm, KeyID: backupKeyID,
		Nonce: nonce, Ciphertext: gcm.Seal(nil, nonce, raw, []byte(backupAAD))}, nil
}

func readBackup(raw json.RawMessage) (backupPayload, error) {
	var payload backupPayload
	var backup encryptedBackup
	if len(raw) > maxBackupBytes || json.Unmarshal(raw, &backup) != nil || backup.Format != backupFormat {
		return payload, errors.New("不是有效的 BalanceMT 加密备份文件")
	}
	if backup.Version != backupVersion || backup.Algorithm != backupAlgorithm || backup.KeyID != backupKeyID {
		return payload, errors.New("备份版本或项目密钥不匹配，请使用当前项目导出的文件")
	}
	gcm, err := backupCipher()
	if err != nil {
		return payload, errors.New("无法初始化备份解密")
	}
	if len(backup.Nonce) != gcm.NonceSize() || len(backup.Ciphertext) < gcm.Overhead() || len(backup.Ciphertext) > maxBackupBytes/2+gcm.Overhead() {
		return payload, errors.New("备份文件格式无效或文件过大")
	}
	plaintext, err := gcm.Open(nil, backup.Nonce, backup.Ciphertext, []byte(backupAAD))
	if err != nil {
		return payload, errors.New("备份无法解密：文件已损坏、被修改，或来自不同项目密钥的程序")
	}
	if err := json.Unmarshal(plaintext, &payload); err != nil {
		return payload, errors.New("备份内容格式无效")
	}
	if err := validateBackupPayload(payload); err != nil {
		return payload, err
	}
	return payload, nil
}

func validateBackupPayload(payload backupPayload) error {
	if payload.Version != 1 || payload.Accounts == nil || len(payload.Accounts) > 1000 {
		return errors.New("备份内容版本无效，或站点数量超过 1000")
	}
	seen := make(map[string]bool)
	for i, input := range payload.Accounts {
		invalid := input.Name == "" || input.Identifier == "" || input.Enabled == nil ||
			(strings.TrimSpace(input.Password) == "" && strings.TrimSpace(input.AccessToken) == "") ||
			(input.BaseProvider != "" && input.BaseProvider != "new-api" && input.BaseProvider != "sub2api") ||
			(input.Provider != "new-api" && input.Provider != "sub2api" && input.Provider != "generic") ||
			input.BalancePath == "" || input.LoginPath == "" || input.IdentifierKey == "" || input.TokenField == "" || input.BalanceField == "" ||
			input.BalanceScale <= 0 || math.IsNaN(input.BalanceScale) || math.IsInf(input.BalanceScale, 0) ||
			math.IsNaN(input.Threshold) || math.IsInf(input.Threshold, 0)
		u, err := url.Parse(input.BaseURL)
		if invalid || err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return fmt.Errorf("备份中第 %d 个站点配置无效", i+1)
		}
		key := backupAccountKey(inferBaseProvider(input), input.BaseURL, input.Identifier)
		if seen[key] {
			return fmt.Errorf("备份中第 %d 个站点重复，请先整理同平台、同地址、同账号的配置", i+1)
		}
		seen[key] = true
	}
	cfg := payload.Settings.Alerts
	usageWindow := payload.Settings.UsageWindowHours
	if usageWindow == 0 {
		usageWindow = 24
	}
	if payload.Settings.MonitorIntervalSeconds < 1 || payload.Settings.MonitorIntervalSeconds > 86400 || usageWindow < 1 || usageWindow > 720 || payload.Settings.FailureAlertThreshold < 1 || payload.Settings.FailureAlertThreshold > 1000 || cfg.SMTPPort < 1 || cfg.SMTPPort > 65535 ||
		(cfg.SMSProvider != "" && cfg.SMSProvider != "twilio" && cfg.SMSProvider != "webhook") {
		return errors.New("备份中的检查间隔或告警配置无效")
	}
	return nil
}

func backupAccountKey(provider, baseURL, identifier string) string {
	// JSON encoding avoids ambiguous separators in user-provided identifiers.
	raw, _ := json.Marshal([]string{provider, strings.TrimRight(baseURL, "/"), identifier})
	return string(raw)
}

func (a *app) snapshotBackup() (backupPayload, error) {
	a.settingsMu.Lock()
	defer a.settingsMu.Unlock()
	payload := backupPayload{Version: 1, ExportedAt: time.Now().UTC().Format(time.RFC3339), Accounts: make([]accountInput, 0)}
	// A single query reads each configuration together with its matching secret.
	rows, err := a.db.Query(`SELECT name,provider,base_provider,base_url,identifier,COALESCE(api_user_id,''),secret_enc,currency,threshold,enabled,COALESCE(login_path,''),COALESCE(balance_path,''),COALESCE(identifier_key,''),COALESCE(token_field,''),COALESCE(balance_field,''),balance_scale FROM accounts ORDER BY id`)
	if err != nil {
		return payload, err
	}
	defer rows.Close()
	for rows.Next() {
		var input accountInput
		var encrypted string
		var enabled int
		if err := rows.Scan(&input.Name, &input.Provider, &input.BaseProvider, &input.BaseURL, &input.Identifier, &input.APIUserID, &encrypted, &input.Currency, &input.Threshold, &enabled, &input.LoginPath, &input.BalancePath, &input.IdentifierKey, &input.TokenField, &input.BalanceField, &input.BalanceScale); err != nil {
			return payload, err
		}
		raw, err := a.decrypt(encrypted)
		if err != nil {
			return payload, errors.New("无法解密站点凭据，请检查当前 ENCRYPTION_KEY")
		}
		var secret accountSecret
		if err := json.Unmarshal(raw, &secret); err != nil {
			return payload, errors.New("站点凭据格式无效")
		}
		input.Password, input.AccessToken = secret.Password, secret.AccessToken
		normalizeAccountInput(&input)
		active := enabled == 1
		input.Enabled = &active
		payload.Accounts = append(payload.Accounts, input)
	}
	if err := rows.Err(); err != nil {
		return payload, err
	}
	a.configMu.RLock()
	payload.Settings = storedAlertSettings{MonitorIntervalSeconds: int(a.monitorInterval / time.Second), UsageWindowHours: a.currentUsageWindowHours(), FailureAlertThreshold: a.currentFailureAlertThreshold(), Alerts: a.alerts}
	a.configMu.RUnlock()
	return payload, validateBackupPayload(payload)
}

func (a *app) importBackup(payload backupPayload, mode string, importAlerts bool) (backupImportResult, error) {
	var result backupImportResult
	if mode != "skip" && mode != "overwrite" {
		return result, errors.New("导入模式必须为 skip 或 overwrite")
	}
	if payload.Settings.UsageWindowHours == 0 {
		payload.Settings.UsageWindowHours = 24
	}
	if payload.Settings.FailureAlertThreshold == 0 {
		payload.Settings.FailureAlertThreshold = 5
	}
	if err := validateBackupPayload(payload); err != nil {
		return result, err
	}
	// Classify imported interfaces using the same rules as the editor.
	payload.Accounts = append([]accountInput(nil), payload.Accounts...)
	for i := range payload.Accounts {
		payload.Accounts[i].LoginPath = normalizeEndpointPath(payload.Accounts[i].LoginPath)
		payload.Accounts[i].BalancePath = normalizeEndpointPath(payload.Accounts[i].BalancePath)
		normalizeAccountInput(&payload.Accounts[i])
		if err := validateAccountPlatform(payload.Accounts[i]); err != nil {
			return result, err
		}
	}
	// Prevent an in-flight balance request from writing old credentials after import.
	a.mu.Lock()
	defer a.mu.Unlock()
	a.settingsMu.Lock()
	defer a.settingsMu.Unlock()
	tx, err := a.db.Begin()
	if err != nil {
		return result, err
	}
	defer tx.Rollback()
	rows, err := tx.Query(`SELECT id,base_provider,base_url,identifier FROM accounts`)
	if err != nil {
		return result, err
	}
	existing := make(map[string][]int64)
	for rows.Next() {
		var id int64
		var provider, baseURL, identifier string
		if err := rows.Scan(&id, &provider, &baseURL, &identifier); err != nil {
			rows.Close()
			return result, err
		}
		key := backupAccountKey(provider, baseURL, identifier)
		existing[key] = append(existing[key], id)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return result, err
	}
	now := time.Now().UTC().Format(time.RFC3339)
	var updatedIDs []int64
	for _, input := range payload.Accounts {
		ids := existing[backupAccountKey(input.BaseProvider, input.BaseURL, input.Identifier)]
		if len(ids) > 0 && mode == "skip" {
			result.Skipped++
			continue
		}
		if len(ids) > 1 {
			return result, errors.New("目标中存在多个相同站点，无法确定覆盖对象，请先整理或选择跳过重复站点")
		}
		encrypted, err := a.encrypt(accountSecret{Identifier: input.Identifier, Password: input.Password, AccessToken: input.AccessToken})
		if err != nil {
			return result, err
		}
		enabled := 0
		if *input.Enabled {
			enabled = 1
		}
		values := []any{input.Name, input.Provider, input.BaseProvider, input.BaseURL, input.Identifier, input.APIUserID, encrypted, input.Currency, input.Threshold, enabled, input.LoginPath, input.BalancePath, input.IdentifierKey, input.TokenField, input.BalanceField, input.BalanceScale}
		if len(ids) == 1 {
			values = append(values, now, ids[0])
			_, err = tx.Exec(`UPDATE accounts SET name=?,provider=?,base_provider=?,base_url=?,identifier=?,api_user_id=?,secret_enc=?,currency=?,threshold=?,enabled=?,login_path=?,balance_path=?,identifier_key=?,token_field=?,balance_field=?,balance_scale=?,balance=0,status='pending',last_error=NULL,last_checked_at=NULL,updated_at=? WHERE id=?`, values...)
			result.Updated++
			updatedIDs = append(updatedIDs, ids[0])
		} else {
			values = append(values, now, now)
			_, err = tx.Exec(`INSERT INTO accounts(name,provider,base_provider,base_url,identifier,api_user_id,secret_enc,currency,threshold,enabled,login_path,balance_path,identifier_key,token_field,balance_field,balance_scale,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, values...)
			result.Added++
		}
		if err != nil {
			return result, err
		}
	}
	if importAlerts {
		encrypted, err := a.encrypt(payload.Settings)
		if err != nil {
			return result, err
		}
		if _, err := tx.Exec(`INSERT INTO app_settings(key,value_enc,updated_at) VALUES(?,?,?) ON CONFLICT(key) DO UPDATE SET value_enc=excluded.value_enc,updated_at=excluded.updated_at`, "alerts", encrypted, now); err != nil {
			return result, err
		}
		result.AlertsImported = true
	}
	if err := tx.Commit(); err != nil {
		return result, err
	}
	if importAlerts {
		a.configMu.Lock()
		a.alerts = payload.Settings.Alerts
		a.monitorInterval = time.Duration(payload.Settings.MonitorIntervalSeconds) * time.Second
		a.usageWindowHours = payload.Settings.UsageWindowHours
		a.failureAlertThreshold = payload.Settings.FailureAlertThreshold
		a.configMu.Unlock()
		select {
		case a.intervalWake <- struct{}{}:
		default:
		}
	}
	a.alertMu.Lock()
	for _, id := range updatedIDs {
		delete(a.alertStates, id)
	}
	a.alertMu.Unlock()
	return result, nil
}

func decodeBackupRequest(w http.ResponseWriter, r *http.Request, dst any) bool {
	defer r.Body.Close()
	r.Body = http.MaxBytesReader(w, r.Body, maxBackupBytes)
	decoder := json.NewDecoder(r.Body)
	err := decoder.Decode(dst)
	if err == nil {
		var extra any
		if decoder.Decode(&extra) == io.EOF {
			return true
		}
	}
	writeJSON(w, http.StatusBadRequest, map[string]any{"error": "备份请求格式不正确，文件最大 8 MB"})
	return false
}

func (a *app) beginBackupRequest(w http.ResponseWriter, r *http.Request) bool {
	w.Header().Set("Cache-Control", "no-store")
	if !a.requireAuth(w, r) {
		return false
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return false
	}
	if !a.backupMu.TryLock() {
		writeJSON(w, http.StatusConflict, map[string]any{"error": "另一个导入或导出正在执行，请稍后重试"})
		return false
	}
	return true
}

func (a *app) handleBackupExport(w http.ResponseWriter, r *http.Request) {
	if !a.beginBackupRequest(w, r) {
		return
	}
	defer a.backupMu.Unlock()
	var input struct{}
	if !decodeBackupRequest(w, r, &input) {
		return
	}
	payload, err := a.snapshotBackup()
	if err != nil {
		writeJSON(w, 500, map[string]any{"error": "导出失败：" + err.Error()})
		return
	}
	backup, err := sealBackup(payload)
	if err != nil {
		writeJSON(w, 500, map[string]any{"error": "无法创建备份"})
		return
	}
	w.Header().Set("Content-Disposition", `attachment; filename="balancemt-`+time.Now().UTC().Format("20060102-150405")+`.balancemt.json"`)
	writeJSON(w, http.StatusOK, backup)
}

func (a *app) handleBackupImport(w http.ResponseWriter, r *http.Request) {
	if !a.beginBackupRequest(w, r) {
		return
	}
	defer a.backupMu.Unlock()
	var input backupImportInput
	if !decodeBackupRequest(w, r, &input) {
		return
	}
	if input.Mode == "" {
		input.Mode = "skip"
	}
	payload, err := readBackup(input.Backup)
	if err != nil {
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	result, err := a.importBackup(payload, input.Mode, input.ImportAlerts)
	if err != nil {
		writeJSON(w, 400, map[string]any{"error": "导入失败，未保存任何更改：" + err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, result)
}
