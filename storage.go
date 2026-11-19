package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

type storagePolicy struct {
	Enabled       bool `json:"enabled"`
	IntervalHours int  `json:"interval_hours"`
}

type cleanupResult struct {
	CheckedAt       string `json:"checked_at"`
	SuccessDeleted  int64  `json:"success_deleted"`
	SnapshotDeleted int64  `json:"snapshot_deleted"`
	FailureDeleted  int64  `json:"failure_deleted"`
	SessionsDeleted int64  `json:"sessions_deleted"`
	DatabaseBefore  int64  `json:"database_before"`
	DatabaseAfter   int64  `json:"database_after"`
	ReclaimedBytes  int64  `json:"reclaimed_bytes"`
	Compacted       bool   `json:"compacted"`
	CompactionNote  string `json:"compaction_note,omitempty"`
}

type storedStorageSettings struct {
	Policy        storagePolicy  `json:"policy"`
	LastCleanup   *cleanupResult `json:"last_cleanup,omitempty"`
	LastAttemptAt string         `json:"last_attempt_at,omitempty"`
	LastError     string         `json:"last_error,omitempty"`
}

type storageStats struct {
	Settings           storagePolicy  `json:"settings"`
	DatabaseBytes      int64          `json:"database_bytes"`
	DatabaseFilesBytes int64          `json:"database_files_bytes"`
	ReusableBytes      int64          `json:"reusable_bytes"`
	OtherDataBytes     int64          `json:"other_data_bytes"`
	DiskTotalBytes     uint64         `json:"disk_total_bytes"`
	DiskAvailableBytes uint64         `json:"disk_available_bytes"`
	DiskError          string         `json:"disk_error,omitempty"`
	SuccessRecords     int64          `json:"success_records"`
	BalanceSnapshots   int64          `json:"balance_snapshots"`
	FailureRecords     int64          `json:"failure_records"`
	ExpiredSessions    int64          `json:"expired_sessions"`
	LastCleanup        *cleanupResult `json:"last_cleanup,omitempty"`
	LastError          string         `json:"last_error,omitempty"`
	NextCleanupAt      string         `json:"next_cleanup_at,omitempty"`
}

func defaultStoragePolicy() storagePolicy {
	return storagePolicy{Enabled: true, IntervalHours: 24}
}

func (p storagePolicy) validate() error {
	if p.IntervalHours < 1 || p.IntervalHours > 168 {
		return errors.New("清理间隔必须在 1 到 168 小时之间")
	}
	return nil
}

func (a *app) readStorageSettings() (storedStorageSettings, error) {
	out := storedStorageSettings{Policy: defaultStoragePolicy()}
	var encrypted string
	err := a.db.QueryRow(`SELECT value_enc FROM app_settings WHERE key='storage'`).Scan(&encrypted)
	if errors.Is(err, sql.ErrNoRows) {
		return out, nil
	}
	if err != nil {
		return out, err
	}
	raw, err := a.decrypt(encrypted)
	if err != nil {
		return out, err
	}
	if err := unmarshalStorage(raw, &out); err != nil {
		return out, err
	}
	return out, out.Policy.validate()
}

func (a *app) saveStorageSettings(s storedStorageSettings) error {
	encrypted, err := a.encrypt(s)
	if err != nil {
		return err
	}
	_, err = a.db.Exec(`INSERT INTO app_settings(key,value_enc,updated_at) VALUES('storage',?,?) ON CONFLICT(key) DO UPDATE SET value_enc=excluded.value_enc,updated_at=excluded.updated_at`, encrypted, time.Now().UTC().Format(time.RFC3339))
	return err
}

func nextStorageCleanup(s storedStorageSettings) time.Time {
	last, err := time.Parse(time.RFC3339, s.LastAttemptAt)
	if err != nil {
		return time.Time{}
	}
	return last.Add(time.Duration(s.Policy.IntervalHours) * time.Hour)
}

func (a *app) databasePath() (string, error) {
	rows, err := a.db.Query(`PRAGMA database_list`)
	if err != nil {
		return "", err
	}
	defer rows.Close()
	for rows.Next() {
		var seq int
		var name, path string
		if err := rows.Scan(&seq, &name, &path); err != nil {
			return "", err
		}
		if name == "main" && path != "" {
			return path, nil
		}
	}
	if err := rows.Err(); err != nil {
		return "", err
	}
	return "", errors.New("无法确定数据库文件位置")
}

func fileBytes(path string) int64 {
	if info, err := os.Stat(path); err == nil {
		return info.Size()
	}
	return 0
}

func (a *app) storageSnapshot() (storageStats, error) {
	var out storageStats
	stored, err := a.readStorageSettings()
	if err != nil {
		return out, err
	}
	out.Settings, out.LastCleanup, out.LastError = stored.Policy, stored.LastCleanup, stored.LastError
	if stored.Policy.Enabled {
		next := nextStorageCleanup(stored)
		if next.IsZero() {
			next = time.Now().UTC()
		}
		out.NextCleanupAt = next.Format(time.RFC3339)
	}
	path, err := a.databasePath()
	if err != nil {
		return out, err
	}
	dir := filepath.Dir(path)
	out.DatabaseBytes = fileBytes(path)
	out.DatabaseFilesBytes = out.DatabaseBytes
	for _, suffix := range []string{"-wal", "-shm", "-journal"} {
		out.DatabaseFilesBytes += fileBytes(path + suffix)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return out, err
	}
	for _, entry := range entries {
		if entry.IsDir() || entry.Type()&os.ModeSymlink != 0 {
			continue
		}
		name := entry.Name()
		if name == filepath.Base(path) || name == filepath.Base(path)+"-wal" || name == filepath.Base(path)+"-shm" || name == filepath.Base(path)+"-journal" {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			return out, err
		}
		out.OtherDataBytes += info.Size()
	}
	var freePages, pageSize int64
	if err := a.db.QueryRow(`PRAGMA freelist_count`).Scan(&freePages); err != nil {
		return out, err
	}
	if err := a.db.QueryRow(`PRAGMA page_size`).Scan(&pageSize); err != nil {
		return out, err
	}
	out.ReusableBytes = freePages * pageSize
	if err := a.db.QueryRow(`SELECT COUNT(*) FROM balance_history WHERE status='ok'`).Scan(&out.SuccessRecords); err != nil {
		return out, err
	}
	if err := a.db.QueryRow(`SELECT COUNT(*) FROM balance_snapshots`).Scan(&out.BalanceSnapshots); err != nil {
		return out, err
	}
	if err := a.db.QueryRow(`SELECT COUNT(*) FROM balance_history WHERE status='error'`).Scan(&out.FailureRecords); err != nil {
		return out, err
	}
	if err := a.db.QueryRow(`SELECT COUNT(*) FROM sessions WHERE expires_at<=?`, time.Now().UTC().Format(time.RFC3339)).Scan(&out.ExpiredSessions); err != nil {
		return out, err
	}
	out.DiskTotalBytes, out.DiskAvailableBytes, err = diskSpace(dir)
	if err != nil {
		out.DiskError = "无法读取数据目录所在磁盘的容量"
	}
	return out, nil
}

func (a *app) handleStorage(w http.ResponseWriter, r *http.Request) {
	if !a.requireAuth(w, r) {
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	switch r.Method {
	case http.MethodGet:
		stats, err := a.storageSnapshot()
		if err != nil {
			log.Printf("storage statistics: %v", err)
			writeJSON(w, 500, map[string]any{"error": "读取存储统计失败"})
			return
		}
		writeJSON(w, 200, stats)
	case http.MethodPut:
		var input storagePolicy
		if !decodeJSON(w, r, &input) {
			return
		}
		if err := input.validate(); err != nil {
			writeJSON(w, 400, map[string]any{"error": err.Error()})
			return
		}
		if !a.storageMu.TryLock() {
			writeJSON(w, 409, map[string]any{"error": "正在清理，请稍后保存设置"})
			return
		}
		defer a.storageMu.Unlock()
		stored, err := a.readStorageSettings()
		if err == nil {
			if stored.Policy.IntervalHours != input.IntervalHours || (!stored.Policy.Enabled && input.Enabled) {
				stored.LastAttemptAt = time.Now().UTC().Format(time.RFC3339)
			}
			stored.Policy = input
			err = a.saveStorageSettings(stored)
		}
		if err != nil {
			log.Printf("save storage settings: %v", err)
			writeJSON(w, 500, map[string]any{"error": "保存存储设置失败"})
			return
		}
		writeJSON(w, 200, map[string]any{"ok": true})
	default:
		http.Error(w, "method not allowed", 405)
	}
}

func (a *app) handleStorageCleanup(w http.ResponseWriter, r *http.Request) {
	if !a.requireAuth(w, r) {
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", 405)
		return
	}
	var input struct {
		Compact bool `json:"compact"`
	}
	if !decodeJSON(w, r, &input) {
		return
	}
	result, err := a.runStorageCleanup(true, input.Compact)
	if errors.Is(err, errStorageBusy) {
		writeJSON(w, 409, map[string]any{"error": err.Error()})
		return
	}
	if err != nil {
		log.Printf("manual storage cleanup: %v", err)
		writeJSON(w, 500, map[string]any{"error": "清理失败，请刷新统计后重试"})
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 200, result)
}

var errStorageBusy = errors.New("已有清理任务正在执行，请稍后重试")

func (a *app) runStorageCleanup(manual, compact bool) (*cleanupResult, error) {
	if !a.storageMu.TryLock() {
		return nil, errStorageBusy
	}
	defer a.storageMu.Unlock()
	stored, err := a.readStorageSettings()
	if err != nil {
		return nil, err
	}
	if !manual && (!stored.Policy.Enabled || time.Now().Before(nextStorageCleanup(stored))) {
		return nil, nil
	}
	stored.LastAttemptAt = time.Now().UTC().Format(time.RFC3339)
	// Persist the attempt first, so a failing cleanup does not retry every minute.
	if err := a.saveStorageSettings(stored); err != nil {
		return nil, err
	}
	result, cleanupErr := a.cleanStorage(manual, compact)
	if cleanupErr != nil {
		stored.LastError = "上次清理未完成，请手动重试"
	} else {
		stored.LastError = ""
		stored.LastCleanup = result
	}
	if err := a.saveStorageSettings(stored); err != nil {
		return result, err
	}
	return result, cleanupErr
}

func (a *app) cleanStorage(manual, compact bool) (*cleanupResult, error) {
	path, err := a.databasePath()
	if err != nil {
		return nil, err
	}
	result := &cleanupResult{CheckedAt: time.Now().UTC().Format(time.RFC3339), DatabaseBefore: fileBytes(path)}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	tx, err := a.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	operations := []struct {
		query string
		args  []any
		count *int64
	}{
		{`DELETE FROM balance_history WHERE status='ok'`, nil, &result.SuccessDeleted},
		{`DELETE FROM balance_snapshots WHERE checked_at<?`, []any{time.Now().UTC().Add(-31 * 24 * time.Hour).Format(time.RFC3339)}, &result.SnapshotDeleted},
		{`DELETE FROM balance_history WHERE status='error' AND id NOT IN (SELECT id FROM balance_history WHERE status='error' ORDER BY id DESC LIMIT 20)`, nil, &result.FailureDeleted},
		{`DELETE FROM sessions WHERE expires_at<=?`, []any{time.Now().UTC().Format(time.RFC3339)}, &result.SessionsDeleted},
	}
	for _, op := range operations {
		r, err := tx.ExecContext(ctx, op.query, op.args...)
		if err != nil {
			return nil, err
		}
		n, err := r.RowsAffected()
		if err != nil {
			return nil, err
		}
		*op.count += n
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	var freePages, pageSize int64
	if err := a.db.QueryRowContext(ctx, `PRAGMA freelist_count`).Scan(&freePages); err != nil {
		return nil, err
	}
	if err := a.db.QueryRowContext(ctx, `PRAGMA page_size`).Scan(&pageSize); err != nil {
		return nil, err
	}
	reusable := freePages * pageSize
	shouldCompact := compact || (!manual && reusable >= 1<<20 && reusable >= fileBytes(path)/4)
	if shouldCompact && reusable > 0 {
		_, available, diskErr := diskSpace(filepath.Dir(path))
		required := uint64(fileBytes(path))*2 + (16 << 20)
		if diskErr != nil || available < required {
			result.CompactionNote = "记录已清理；剩余磁盘空间不足或无法读取，跳过压缩，数据库空闲页可继续复用。"
		} else if _, err := a.db.ExecContext(ctx, `VACUUM`); err != nil {
			result.CompactionNote = "记录已清理；本次压缩未完成，可稍后重试。"
			log.Printf("compact storage database: %v", err)
		} else {
			result.Compacted = true
		}
	}
	result.DatabaseAfter = fileBytes(path)
	if result.DatabaseBefore > result.DatabaseAfter {
		result.ReclaimedBytes = result.DatabaseBefore - result.DatabaseAfter
	}
	return result, nil
}

func (a *app) storageMaintenanceLoop() {
	tick := time.NewTicker(time.Minute)
	defer tick.Stop()
	for {
		if _, err := a.runStorageCleanup(false, false); err != nil && !errors.Is(err, errStorageBusy) {
			log.Printf("scheduled storage cleanup: %v", err)
		}
		<-tick.C
	}
}

// Keep settings decoding local to storage management; account and alert secrets
// remain encrypted by the existing deployment key.
func unmarshalStorage(raw []byte, out *storedStorageSettings) error {
	if err := json.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("decode storage settings: %w", err)
	}
	return nil
}
