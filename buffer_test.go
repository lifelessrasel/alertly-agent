package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/lifelessrasel/alertly-agent/internal/collect"
)

func TestPendingSamplesSurviveARestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pending.json")
	now := time.Now().UTC().Truncate(time.Second)
	fresh := collect.Sample{RecordedAt: now.Format(time.RFC3339), ProcessCount: 42}
	stale := collect.Sample{RecordedAt: now.Add(-48 * time.Hour).Format(time.RFC3339)}

	savePending(path, []collect.Sample{stale, fresh})
	loaded := loadPending(path, now.Add(-maxSampleAge))

	if len(loaded) != 1 || loaded[0].ProcessCount != 42 || !loaded[0].TakenAt().Equal(now) {
		t.Fatalf("got %+v, want only the fresh sample with its collection time", loaded)
	}

	savePending(path, nil)
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("expected the buffer file to be removed once everything is sent, got %v", err)
	}
}

func TestPendingIsDisabledWithoutAStateDirectory(t *testing.T) {
	savePending("", []collect.Sample{{RecordedAt: time.Now().UTC().Format(time.RFC3339)}})

	if loaded := loadPending("", time.Time{}); loaded != nil {
		t.Fatalf("got %+v, want nothing", loaded)
	}
}
