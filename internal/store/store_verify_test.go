package store

import (
	"database/sql"
	"errors"
	"path/filepath"
	"testing"
)

func openTestStore(t *testing.T) *Store {
	t.Helper()
	return openTestStoreAt(t, filepath.Join(t.TempDir(), "test.db"))
}

func openTestStoreAt(t *testing.T, path string) *Store {
	t.Helper()
	s, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

// TestWALMode verifies WAL journal mode and busy_timeout are applied on open.
func TestWALMode(t *testing.T) {
	s := openTestStore(t)
	var mode string
	if err := s.db.QueryRow("PRAGMA journal_mode").Scan(&mode); err != nil {
		t.Fatalf("read journal_mode: %v", err)
	}
	if mode != "wal" {
		t.Fatalf("journal_mode = %q, want wal", mode)
	}
	var timeout int
	if err := s.db.QueryRow("PRAGMA busy_timeout").Scan(&timeout); err != nil {
		t.Fatalf("read busy_timeout: %v", err)
	}
	if timeout != 5000 {
		t.Fatalf("busy_timeout = %d, want 5000", timeout)
	}
}

// TestMigrateIdempotent verifies that opening the same database twice (and
// re-running all migrations) keeps user_version at the highest migration
// version and does not corrupt data.
func TestMigrateIdempotent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.db")
	s := openTestStoreAt(t, path)

	var version int
	if err := s.db.QueryRow("PRAGMA user_version").Scan(&version); err != nil {
		t.Fatalf("read user_version: %v", err)
	}
	if version != migrations[len(migrations)-1].version {
		t.Fatalf("user_version = %d, want %d", version, migrations[len(migrations)-1].version)
	}

	if err := s.UpsertSub("demo", map[string]any{"name": "demo"}, "bottom"); err != nil {
		t.Fatalf("UpsertSub: %v", err)
	}

	// Re-open the same file: migrations must be skipped and data preserved.
	s2, err := Open(path)
	if err != nil {
		t.Fatalf("re-open: %v", err)
	}
	defer s2.Close()

	var version2 int
	if err := s2.db.QueryRow("PRAGMA user_version").Scan(&version2); err != nil {
		t.Fatalf("read user_version after reopen: %v", err)
	}
	if version2 != version {
		t.Fatalf("user_version changed on reopen: %d -> %d", version, version2)
	}
	subs, err := s2.ListSubs()
	if err != nil {
		t.Fatalf("ListSubs after reopen: %v", err)
	}
	if len(subs) != 1 || subs[0]["name"] != "demo" {
		t.Fatalf("subs after reopen = %v, want [demo]", subs)
	}
}

// TestRenameConflict verifies that renaming onto an existing name reports
// ErrNameConflict instead of a raw UNIQUE constraint error.
func TestRenameConflict(t *testing.T) {
	s := openTestStore(t)
	if err := s.UpsertSub("a", map[string]any{"name": "a"}, "bottom"); err != nil {
		t.Fatalf("UpsertSub a: %v", err)
	}
	if err := s.UpsertSub("b", map[string]any{"name": "b"}, "bottom"); err != nil {
		t.Fatalf("UpsertSub b: %v", err)
	}
	err := s.RenameSub("a", "b", map[string]any{"name": "b"})
	if !errors.Is(err, ErrNameConflict) {
		t.Fatalf("RenameSub conflict err = %v, want ErrNameConflict", err)
	}
	// The conflicting rename must not have been applied.
	got, err := s.GetSub("a")
	if err != nil {
		t.Fatalf("GetSub a: %v", err)
	}
	if got == nil || got["name"] != "a" {
		t.Fatalf("sub a was modified by failed rename: %v", got)
	}
	// Renaming to a free name must still succeed.
	if err := s.RenameSub("a", "c", map[string]any{"name": "c"}); err != nil {
		t.Fatalf("RenameSub a->c: %v", err)
	}
}

// TestWithTxRollback verifies that WithTx rolls back every write in the
// transaction when fn returns an error, and commits when it returns nil.
func TestWithTxRollback(t *testing.T) {
	s := openTestStore(t)
	if err := s.UpsertSub("keep", map[string]any{"name": "keep"}, "bottom"); err != nil {
		t.Fatalf("UpsertSub: %v", err)
	}

	sentinel := errors.New("boom")
	err := s.WithTx(func(tx *sql.Tx) error {
		if err := DeleteSubTx(tx, "keep"); err != nil {
			return err
		}
		if err := UpsertCollectionTx(tx, "c1", map[string]any{"name": "c1"}, "bottom"); err != nil {
			return err
		}
		return sentinel
	})
	if !errors.Is(err, sentinel) {
		t.Fatalf("WithTx err = %v, want sentinel", err)
	}
	subs, err := s.ListSubs()
	if err != nil {
		t.Fatalf("ListSubs: %v", err)
	}
	if len(subs) != 1 || subs[0]["name"] != "keep" {
		t.Fatalf("subs after rollback = %v, want [keep]", subs)
	}
	cols, err := s.ListCollections()
	if err != nil {
		t.Fatalf("ListCollections: %v", err)
	}
	if len(cols) != 0 {
		t.Fatalf("collections after rollback = %v, want empty", cols)
	}

	// Successful transaction commits.
	if err := s.WithTx(func(tx *sql.Tx) error {
		return UpsertCollectionTx(tx, "c2", map[string]any{"name": "c2"}, "bottom")
	}); err != nil {
		t.Fatalf("WithTx commit: %v", err)
	}
	cols, err = s.ListCollections()
	if err != nil {
		t.Fatalf("ListCollections: %v", err)
	}
	if len(cols) != 1 || cols[0]["name"] != "c2" {
		t.Fatalf("collections after commit = %v, want [c2]", cols)
	}
}
