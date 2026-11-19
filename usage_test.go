package main

import (
	"testing"
	"time"
)

func TestAccountUsageCalculatesConsumptionAndRunway(t *testing.T) {
	a := newBackupTestApp(t, "usage-test")
	id, err := a.createAccount(backupTestAccount())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 11, 19, 12, 0, 0, 0, time.UTC)
	samples := []struct {
		balance float64
		at      time.Time
	}{
		{100, now.Add(-24 * time.Hour)},
		{80, now.Add(-12 * time.Hour)},
		{70, now},
	}
	for _, sample := range samples {
		if _, err := a.db.Exec("INSERT INTO balance_snapshots(account_id,balance,checked_at) VALUES(?,?,?)", id, sample.balance, sample.at.Format(time.RFC3339)); err != nil {
			t.Fatal(err)
		}
	}
	usage, err := a.accountUsage(id, 70, now, 24)
	if err != nil {
		t.Fatal(err)
	}
	if !usage.Ready || usage.Samples != 3 || usage.Consumption != 30 {
		t.Fatalf("unexpected usage: %+v", usage)
	}
	if usage.EstimatedHours != 56 {
		t.Fatalf("estimated hours = %v, want 56", usage.EstimatedHours)
	}
}

func TestAccountUsageIgnoresTopUpsWhenSummingConsumption(t *testing.T) {
	a := newBackupTestApp(t, "usage-topup-test")
	id, err := a.createAccount(backupTestAccount())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 11, 19, 12, 0, 0, 0, time.UTC)
	samples := []struct {
		balance float64
		at      time.Time
	}{
		{100, now.Add(-24 * time.Hour)}, {80, now.Add(-18 * time.Hour)},
		{120, now.Add(-12 * time.Hour)}, {110, now},
	}
	for _, sample := range samples {
		if _, err := a.db.Exec("INSERT INTO balance_snapshots(account_id,balance,checked_at) VALUES(?,?,?)", id, sample.balance, sample.at.Format(time.RFC3339)); err != nil {
			t.Fatal(err)
		}
	}
	usage, err := a.accountUsage(id, 110, now, 24)
	if err != nil {
		t.Fatal(err)
	}
	if !usage.Ready || usage.Consumption != 30 {
		t.Fatalf("unexpected usage after top-up: %+v", usage)
	}
}

func TestRecordBalanceSnapshotPeriodicallyAndOnChange(t *testing.T) {
	a := newBackupTestApp(t, "usage-sampling-test")
	id, err := a.createAccount(backupTestAccount())
	if err != nil {
		t.Fatal(err)
	}
	start := time.Date(2026, 11, 19, 12, 0, 0, 0, time.UTC)
	for _, step := range []struct {
		minutes int
		balance float64
		count   int
	}{
		{0, 100, 1}, {1, 100, 1}, {5, 100, 2}, {6, 90, 3}, {6, 90, 3},
	} {
		at := start.Add(time.Duration(step.minutes) * time.Minute).Format(time.RFC3339)
		if err := a.recordBalanceSnapshot(id, step.balance, at); err != nil {
			t.Fatal(err)
		}
		var count int
		if err := a.db.QueryRow("SELECT COUNT(*) FROM balance_snapshots WHERE account_id=?", id).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != step.count {
			t.Fatalf("at %s: got %d samples, want %d", at, count, step.count)
		}
	}
	usage, err := a.accountUsage(id, 90, start.Add(6*time.Minute), 24)
	if err != nil || !usage.Ready || usage.Consumption != 10 {
		t.Fatalf("unexpected usage: %+v, %v", usage, err)
	}
}

func TestAccountUsageNoConsumption(t *testing.T) {
	a := newBackupTestApp(t, "usage-flat-test")
	id, err := a.createAccount(backupTestAccount())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 11, 19, 12, 0, 0, 0, time.UTC)
	for _, at := range []time.Time{now.Add(-5 * time.Minute), now} {
		if err := a.recordBalanceSnapshot(id, 100, at.Format(time.RFC3339)); err != nil {
			t.Fatal(err)
		}
	}
	usage, err := a.accountUsage(id, 100, now, 24)
	if err != nil || !usage.Ready || usage.Consumption != 0 {
		t.Fatalf("unexpected usage: %+v, %v", usage, err)
	}
}
