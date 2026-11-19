package main

import "testing"

func TestMaybeAlertRequiresConsecutiveFailures(t *testing.T) {
	a := newBackupTestApp(t, "failure-threshold-test")
	a.failureAlertThreshold = 3
	account := Account{ID: 42, Name: "test", Provider: "new-api", Status: "error", Error: "request failed"}

	for i := 1; i <= 2; i++ {
		a.maybeAlert(account)
		a.alertMu.Lock()
		state := a.alertStates[account.ID]
		a.alertMu.Unlock()
		if state.failureCount != i || state.checkError {
			t.Fatalf("failure %d state = %+v", i, state)
		}
	}

	a.maybeAlert(account)
	a.alertMu.Lock()
	state := a.alertStates[account.ID]
	a.alertMu.Unlock()
	if state.failureCount != 3 || !state.checkError {
		t.Fatalf("threshold state = %+v", state)
	}

	a.maybeAlert(account)
	a.alertMu.Lock()
	state = a.alertStates[account.ID]
	a.alertMu.Unlock()
	if state.failureCount != 4 || !state.checkError {
		t.Fatalf("repeated failure state = %+v", state)
	}

	account.Status = "ok"
	a.maybeAlert(account)
	a.alertMu.Lock()
	state = a.alertStates[account.ID]
	a.alertMu.Unlock()
	if state.failureCount != 0 || state.checkError {
		t.Fatalf("recovery state = %+v", state)
	}
}
