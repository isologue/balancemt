package main

import (
	"database/sql"
	"errors"
	"math"
	"net/http"
	"strings"
)

type platformTemplate struct {
	LoginPath     string  `json:"login_path"`
	BalancePath   string  `json:"balance_path"`
	IdentifierKey string  `json:"identifier_key"`
	TokenField    string  `json:"token_field"`
	BalanceField  string  `json:"balance_field"`
	BalanceScale  float64 `json:"balance_scale"`
}

var platformTemplates = map[string]platformTemplate{
	"new-api": {"/api/user/login", "/api/user/self", "username", "data.access_token", "data.quota", 500000},
	"sub2api": {"/api/v1/auth/login", "/api/v1/auth/me", "email", "data.access_token", "data.balance", 1},
}

func accountPlatformFields(input accountInput) platformTemplate {
	return platformTemplate{input.LoginPath, input.BalancePath, input.IdentifierKey, input.TokenField, input.BalanceField, input.BalanceScale}
}

func inferBaseProvider(input accountInput) string {
	if input.BaseProvider != "" {
		return input.BaseProvider
	}
	if input.Provider == "new-api" || input.Provider == "sub2api" {
		return input.Provider
	}
	// Older custom accounts did not store their template source. Preserve their
	// actual interface values and infer the source only for the editor.
	if strings.HasPrefix(input.LoginPath, "/api/v1/auth/") || strings.HasPrefix(input.BalancePath, "/api/v1/auth/") || input.IdentifierKey == "email" {
		return "sub2api"
	}
	return "new-api"
}

func classifyAccountPlatform(input *accountInput) {
	input.Provider = input.BaseProvider
	if template, ok := platformTemplates[input.BaseProvider]; ok && accountPlatformFields(*input) != template {
		input.Provider = "generic"
	}
}

func normalizeAccountPlatform(input *accountInput) {
	input.Provider = strings.ToLower(strings.TrimSpace(input.Provider))
	input.BaseProvider = strings.ToLower(strings.TrimSpace(input.BaseProvider))
	input.LoginPath = strings.TrimSpace(input.LoginPath)
	input.BalancePath = strings.TrimSpace(input.BalancePath)
	input.IdentifierKey = strings.TrimSpace(input.IdentifierKey)
	input.TokenField = strings.TrimSpace(input.TokenField)
	input.BalanceField = strings.TrimSpace(input.BalanceField)
	if input.Provider != "" && input.Provider != "generic" && input.Provider != "new-api" && input.Provider != "sub2api" {
		return
	}
	noInterface := accountPlatformFields(*input) == (platformTemplate{})
	input.BaseProvider = inferBaseProvider(*input)
	template, ok := platformTemplates[input.BaseProvider]
	if !ok {
		return
	}
	if input.LoginPath == "" {
		input.LoginPath = template.LoginPath
	}
	if input.BalancePath == "" {
		input.BalancePath = template.BalancePath
	}
	if input.IdentifierKey == "" {
		input.IdentifierKey = template.IdentifierKey
	}
	if input.TokenField == "" {
		input.TokenField = template.TokenField
	}
	if input.BalanceField == "" {
		input.BalanceField = template.BalanceField
	}
	if input.BalanceScale == 0 && noInterface {
		input.BalanceScale = template.BalanceScale
	}
	classifyAccountPlatform(input)
}

func validateAccountPlatform(input accountInput) error {
	if _, ok := platformTemplates[input.BaseProvider]; !ok {
		return errors.New("基础平台必须为 New-API 或 Sub2API")
	}
	if input.Provider != "new-api" && input.Provider != "sub2api" && input.Provider != "generic" {
		return errors.New("平台类型无效")
	}
	if input.BalanceScale <= 0 || math.IsNaN(input.BalanceScale) || math.IsInf(input.BalanceScale, 0) {
		return errors.New("余额除数必须为大于 0 的数字")
	}
	if !strings.HasPrefix(input.LoginPath, "/") || !strings.HasPrefix(input.BalancePath, "/") {
		return errors.New("接口路径必须以 / 开头")
	}
	return nil
}

func migrateAccountPlatforms(db *sql.DB) error {
	rows, err := db.Query(`SELECT id,provider,COALESCE(login_path,''),COALESCE(balance_path,''),COALESCE(identifier_key,''),COALESCE(token_field,''),COALESCE(balance_field,''),balance_scale FROM accounts WHERE base_provider=''`)
	if err != nil {
		return err
	}
	type migration struct {
		id    int64
		input accountInput
	}
	var pending []migration
	for rows.Next() {
		var item migration
		input := &item.input
		if err := rows.Scan(&item.id, &input.Provider, &input.LoginPath, &input.BalancePath, &input.IdentifierKey, &input.TokenField, &input.BalanceField, &input.BalanceScale); err != nil {
			rows.Close()
			return err
		}
		input.BaseProvider = inferBaseProvider(*input)
		classifyAccountPlatform(input)
		pending = append(pending, item)
	}
	err = rows.Err()
	rows.Close()
	if err != nil || len(pending) == 0 {
		return err
	}
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, item := range pending {
		if _, err := tx.Exec(`UPDATE accounts SET base_provider=?,provider=? WHERE id=? AND base_provider=''`, item.input.BaseProvider, item.input.Provider, item.id); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (a *app) handlePlatforms(w http.ResponseWriter, r *http.Request) {
	if !a.requireAuth(w, r) {
		return
	}
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, http.StatusOK, platformTemplates)
}
