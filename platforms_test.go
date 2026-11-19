package main

import (
	"encoding/json"
	"math"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
)

func TestPlatformClassification(t *testing.T) {
	for base := range platformTemplates {
		t.Run(base, func(t *testing.T) {
			initial := accountInput{Provider: base}
			normalizeAccountInput(&initial)
			if initial.BaseProvider != base || initial.Provider != base || accountPlatformFields(initial) != platformTemplates[base] {
				t.Fatal("wrong defaults")
			}
			edits := map[string]func(*accountInput){
				"login":      func(v *accountInput) { v.LoginPath += "?compat=1" },
				"balance":    func(v *accountInput) { v.BalancePath = "/compat/me" },
				"identifier": func(v *accountInput) { v.IdentifierKey = "login" },
				"token":      func(v *accountInput) { v.TokenField = "result.token" },
				"field":      func(v *accountInput) { v.BalanceField = "result.credit" },
				"scale":      func(v *accountInput) { v.BalanceScale = 2.5 },
			}
			for name, edit := range edits {
				t.Run(name, func(t *testing.T) {
					v := initial
					edit(&v)
					fields := accountPlatformFields(v)
					normalizeAccountInput(&v)
					if v.Provider != "generic" || v.BaseProvider != base || accountPlatformFields(v) != fields {
						t.Fatal("custom values were overridden or not classified")
					}
					v = initial
					v.Provider = "generic"
					normalizeAccountInput(&v)
					if v.Provider != base {
						t.Fatal("restoring defaults did not restore built-in classification")
					}
				})
			}
			initial.Name, initial.BaseURL, initial.Identifier, initial.APIUserID = "Changed", "https://changed.test", "another", "99"
			initial.LoginPath = "  " + initial.LoginPath + "  "
			normalizeAccountInput(&initial)
			if initial.Provider != base {
				t.Fatal("ordinary fields or surrounding spaces changed platform")
			}
		})
	}
}

func TestPlatformValidation(t *testing.T) {
	for name, edit := range map[string]func(*accountInput){
		"unknown-base":     func(v *accountInput) { v.BaseProvider = "unsupported" },
		"unknown-provider": func(v *accountInput) { v.Provider = "unsupported" },
		"zero":             func(v *accountInput) { v.BalanceScale = 0 },
		"negative":         func(v *accountInput) { v.BalanceScale = -1 },
		"nan":              func(v *accountInput) { v.BalanceScale = math.NaN() },
		"infinity":         func(v *accountInput) { v.BalanceScale = math.Inf(1) },
		"path":             func(v *accountInput) { v.BalancePath = "https://other.test/me" },
	} {
		t.Run(name, func(t *testing.T) {
			v := backupTestAccount()
			edit(&v)
			normalizeAccountInput(&v)
			if validateAccountPlatform(v) == nil {
				t.Fatal("invalid configuration accepted")
			}
		})
	}
}

func TestCustomAccountSaveAndRestore(t *testing.T) {
	a := newBackupTestApp(t, "platform-save")
	input := backupTestAccount()
	input.Provider = "new-api" // The server must derive classification from fields.
	id, err := a.createAccount(input)
	if err != nil {
		t.Fatal(err)
	}
	accounts, err := a.listAccounts()
	if err != nil {
		t.Fatal(err)
	}
	if len(accounts) != 1 || accounts[0].Provider != "generic" || accounts[0].BaseProvider != "new-api" || accounts[0].LoginPath != input.LoginPath {
		t.Fatal("custom fields were not persisted")
	}
	input.Name = "renamed"
	input.Password, input.AccessToken = "", ""
	if err := a.updateAccount(id, input); err != nil {
		t.Fatal(err)
	}
	snapshot, err := a.snapshotBackup()
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Accounts[0].Password != "station-secret" || snapshot.Accounts[0].AccessToken != "station-token" || snapshot.Accounts[0].Provider != "generic" {
		t.Fatal("editing lost credentials or custom classification")
	}
	input.LoginPath = platformTemplates["new-api"].LoginPath
	if err := a.updateAccount(id, input); err != nil {
		t.Fatal(err)
	}
	accounts, err = a.listAccounts()
	if err != nil {
		t.Fatal(err)
	}
	if accounts[0].Provider != "new-api" || accounts[0].BaseProvider != "new-api" {
		t.Fatal("saved defaults did not restore platform")
	}
}

func TestLegacyPlatformMigrationPreservesConfiguration(t *testing.T) {
	a := newBackupTestApp(t, "migration")
	a.db.SetMaxOpenConns(1)
	customNew := backupTestAccount()
	customSub := backupTestAccount()
	customSub.Name = "Sub"
	customSub.Provider = "sub2api"
	customSub.BaseProvider = "sub2api"
	customSub.LoginPath = "/api/v1/auth/login?compat=1"
	customSub.IdentifierKey = "email"
	defaultNew := backupTestAccount()
	defaultNew.Name = "Default"
	defaultNew.Provider = "new-api"
	defaultNew.LoginPath = "/api/user/login"
	for _, input := range []accountInput{customNew, customSub, defaultNew} {
		if _, err := a.createAccount(input); err != nil {
			t.Fatal(err)
		}
	}
	fingerprint := func() []string {
		rows, err := a.db.Query(`SELECT name,base_url,identifier,api_user_id,secret_enc,currency,threshold,enabled,login_path,balance_path,identifier_key,token_field,balance_field,balance_scale,created_at,updated_at FROM accounts ORDER BY id`)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		var out []string
		for rows.Next() {
			values := make([]any, 16)
			ptrs := make([]any, 16)
			for i := range values {
				ptrs[i] = &values[i]
			}
			if err := rows.Scan(ptrs...); err != nil {
				t.Fatal(err)
			}
			raw, _ := json.Marshal(values)
			out = append(out, string(raw))
		}
		if err := rows.Err(); err != nil {
			t.Fatal(err)
		}
		return out
	}
	before := fingerprint()
	if _, err := a.db.Exec(`ALTER TABLE accounts DROP COLUMN base_provider`); err != nil {
		t.Fatal(err)
	}
	if err := initDB(a.db); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, fingerprint()) {
		t.Fatal("migration changed existing settings or credentials")
	}
	accounts, err := a.listAccounts()
	if err != nil {
		t.Fatal(err)
	}
	expected := map[string][2]string{"CC": {"generic", "new-api"}, "Sub": {"generic", "sub2api"}, "Default": {"new-api", "new-api"}}
	for _, v := range accounts {
		if expected[v.Name] != [2]string{v.Provider, v.BaseProvider} {
			t.Fatal("wrong legacy classification")
		}
	}
	if err := initDB(a.db); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, fingerprint()) {
		t.Fatal("repeat migration changed configuration")
	}
}

func TestCustomPlatformBalanceFlow(t *testing.T) {
	for _, base := range []string{"sub2api", "new-api"} {
		t.Run(base, func(t *testing.T) {
			var calls []string
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls = append(calls, r.Method+" "+r.URL.RequestURI())
				w.Header().Set("Content-Type", "application/json")
				switch r.URL.Path {
				case "/compat/login":
					var body map[string]string
					if json.NewDecoder(r.Body).Decode(&body) != nil || body[platformTemplates[base].IdentifierKey] != "user" || body["password"] != "password" {
						t.Error("incorrect login fields")
					}
					w.Write([]byte(`{"result":{"token":"test-token"}}`))
				case "/compat/balance":
					if r.Header.Get("Authorization") != "Bearer test-token" || r.Header.Get("New-Api-User") != "42" {
						t.Error("authentication headers were lost")
					}
					w.Write([]byte(`{"result":{"credits":125}}`))
				default:
					t.Error("unexpected endpoint")
					http.NotFound(w, r)
				}
			}))
			defer server.Close()
			a := newBackupTestApp(t, "flow")
			a.httpClient = server.Client()
			input := accountInput{Name: "Flow", Provider: base, BaseProvider: base, BaseURL: server.URL, Identifier: "user", Password: "password", APIUserID: "42", LoginPath: "/compat/login?test=1", BalancePath: "/compat/balance", IdentifierKey: platformTemplates[base].IdentifierKey, TokenField: "result.token", BalanceField: "result.credits", BalanceScale: 2.5}
			id, err := a.createAccount(input)
			if err != nil {
				t.Fatal(err)
			}
			v, err := a.checkAccount(id)
			if err != nil {
				t.Fatal(err)
			}
			if v.Balance != 50 || v.Provider != "generic" || v.BaseProvider != base || v.Status != "ok" {
				t.Fatal("custom balance query did not use persisted configuration")
			}
			if strings.Join(calls, ",") != "POST /compat/login?test=1,GET /compat/balance" {
				t.Fatal("unexpected request order")
			}
		})
	}
}

func TestBackupKeepsBasePlatformAndDeduplicates(t *testing.T) {
	source := newBackupTestApp(t, "sub-source")
	input := backupTestAccount()
	input.Provider = "sub2api"
	input.BaseProvider = "sub2api"
	input.LoginPath = "/compat/login"
	input.IdentifierKey = "account_email"
	if _, err := source.createAccount(input); err != nil {
		t.Fatal(err)
	}
	payload, err := source.snapshotBackup()
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := sealBackup(payload)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(sealed)
	restored, err := readBackup(raw)
	if err != nil {
		t.Fatal(err)
	}
	dest := newBackupTestApp(t, "sub-destination")
	defaults := accountInput{Name: input.Name, Provider: "sub2api", BaseURL: input.BaseURL, Identifier: input.Identifier, AccessToken: input.AccessToken, Enabled: input.Enabled}
	if _, err := dest.createAccount(defaults); err != nil {
		t.Fatal(err)
	}
	result, err := dest.importBackup(restored, "skip", false)
	if err != nil {
		t.Fatal(err)
	}
	if result.Skipped != 1 || result.Added != 0 {
		t.Fatal("custom and default accounts of same base platform were duplicated")
	}
	result, err = dest.importBackup(restored, "overwrite", false)
	if err != nil {
		t.Fatal(err)
	}
	if result.Updated != 1 {
		t.Fatal("existing account was not overwritten")
	}
	snapshot, err := dest.snapshotBackup()
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Accounts[0].BaseProvider != "sub2api" || snapshot.Accounts[0].Provider != "generic" || snapshot.Accounts[0].IdentifierKey != "account_email" || snapshot.Accounts[0].LoginPath != "/compat/login" {
		t.Fatal("custom Sub2API base or interface was lost")
	}
	// Duplicate entries also share an identity before the transaction begins.
	duplicate := payload.Accounts[0]
	duplicate.Provider = "sub2api"
	duplicate.LoginPath = platformTemplates["sub2api"].LoginPath
	payload.Accounts = append(payload.Accounts, duplicate)
	if validateBackupPayload(payload) == nil {
		t.Fatal("duplicate default and custom entries accepted")
	}
}
