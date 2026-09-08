package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	_ "modernc.org/sqlite"
)

// Store wraps the SQLite database and provides typed accessors for each
// entity type.
type Store struct {
	db *sql.DB
}

// Open opens (creating if needed) the SQLite database at path.
func Open(path string) (*Store, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, fmt.Errorf("create data dir: %w", err)
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	// WAL + busy_timeout make concurrent (multi-process) access wait on the
	// database lock instead of failing immediately with SQLITE_BUSY.
	for _, pragma := range []string{
		"PRAGMA journal_mode=WAL",
		"PRAGMA busy_timeout=5000",
		"PRAGMA foreign_keys=ON",
	} {
		if _, err := db.Exec(pragma); err != nil {
			db.Close()
			return nil, fmt.Errorf("exec %s: %w", pragma, err)
		}
	}
	s := &Store{db: db}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) Close() error {
	return s.db.Close()
}

// migration is a single, ordered schema migration step. The version is the
// PRAGMA user_version value the database gets after fn runs successfully.
type migration struct {
	version int
	fn      func(tx *sql.Tx) error
}

// migrations lists every schema version in order. The initial schema is v1;
// future migrations must be appended below with the next sequential version
// and must be written so that they only run on databases at the previous
// version. Never modify an existing migration once it has shipped.
var migrations = []migration{
	{version: 1, fn: migrateV1InitialSchema},
	// Future migrations append here, e.g. {version: 2, fn: migrateV2...}.
}

// migrateV1InitialSchema creates the base tables. It is idempotent so that
// databases created by older builds (before user_version tracking existed)
// are brought to v1 without touching existing data.
func migrateV1InitialSchema(tx *sql.Tx) error {
	schema := []string{
		`CREATE TABLE IF NOT EXISTS subs (
			id   INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT NOT NULL UNIQUE,
			data TEXT NOT NULL,
			pos  INTEGER NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS collections (
			id   INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT NOT NULL UNIQUE,
			data TEXT NOT NULL,
			pos  INTEGER NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS files (
			id   INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT NOT NULL UNIQUE,
			data TEXT NOT NULL,
			pos  INTEGER NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS tokens (
			id   INTEGER PRIMARY KEY AUTOINCREMENT,
			token TEXT NOT NULL UNIQUE,
			data TEXT NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS settings (
			key   TEXT PRIMARY KEY,
			value TEXT NOT NULL
		)`,
	}
	for _, q := range schema {
		if _, err := tx.Exec(q); err != nil {
			return err
		}
	}
	return nil
}

// migrate applies every pending migration inside its own transaction and
// bumps PRAGMA user_version after each one, so re-opening the database is
// a no-op (idempotent) once all migrations have been applied.
func (s *Store) migrate() error {
	var current int
	if err := s.db.QueryRow("PRAGMA user_version").Scan(&current); err != nil {
		return fmt.Errorf("read user_version: %w", err)
	}
	for _, m := range migrations {
		if m.version <= current {
			continue
		}
		tx, err := s.db.Begin()
		if err != nil {
			return err
		}
		if err := m.fn(tx); err != nil {
			tx.Rollback()
			return fmt.Errorf("migration v%d: %w", m.version, err)
		}
		// user_version is a transactional header field, so bumping it inside
		// the same tx keeps schema and version atomically consistent.
		if _, err := tx.Exec(fmt.Sprintf("PRAGMA user_version = %d", m.version)); err != nil {
			tx.Rollback()
			return fmt.Errorf("set user_version to %d: %w", m.version, err)
		}
		if err := tx.Commit(); err != nil {
			return err
		}
		current = m.version
	}
	return nil
}

// WithTx runs fn inside a single SQLite transaction. If fn returns an error
// the transaction is rolled back and the error is propagated; otherwise the
// transaction is committed. Use it to group multi-step writes so the store
// never ends up in a partially-updated state.
func (s *Store) WithTx(fn func(tx *sql.Tx) error) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	if err := fn(tx); err != nil {
		tx.Rollback()
		return err
	}
	return tx.Commit()
}

// ---- generic helpers ----

// listEntity loads all rows of a table ordered by position, unmarshalling
// each row's data JSON into the provided constructor result.
func listEntity[T any](s *Store, table string, dest *[]T) error {
	rows, err := s.db.Query(fmt.Sprintf("SELECT data FROM %s ORDER BY pos ASC, id ASC", table))
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var raw string
		if err := rows.Scan(&raw); err != nil {
			return err
		}
		var item T
		if err := json.Unmarshal([]byte(raw), &item); err != nil {
			return err
		}
		*dest = append(*dest, item)
	}
	return rows.Err()
}

func getEntity[T any](s *Store, table, name string, dest *T) (bool, error) {
	var raw string
	err := s.db.QueryRow(fmt.Sprintf("SELECT data FROM %s WHERE name = ?", table), name).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if err := json.Unmarshal([]byte(raw), dest); err != nil {
		return false, err
	}
	return true, nil
}

func upsertEntity[T any](s *Store, table, name string, item T, position string) error {
	data, err := json.Marshal(item)
	if err != nil {
		return err
	}
	var pos int
	if position == "top" {
		err = s.db.QueryRow(fmt.Sprintf("SELECT COALESCE(MIN(pos), 1) - 1 FROM %s", table)).Scan(&pos)
		if err != nil {
			return err
		}
	} else {
		err = s.db.QueryRow(fmt.Sprintf("SELECT COALESCE(MAX(pos), 0) + 1 FROM %s", table)).Scan(&pos)
		if err != nil {
			return err
		}
	}
	_, err = s.db.Exec(
		fmt.Sprintf("INSERT INTO %s (name, data, pos) VALUES (?, ?, ?) ON CONFLICT(name) DO UPDATE SET data = excluded.data", table),
		name, string(data), pos,
	)
	return err
}

func deleteEntity(s *Store, table, name string) error {
	_, err := s.db.Exec(fmt.Sprintf("DELETE FROM %s WHERE name = ?", table), name)
	return err
}

// ---- subs ----

// ListSubs returns all subscriptions.
func (s *Store) ListSubs() ([]map[string]any, error) {
	out := []map[string]any{}
	err := s.queryMaps("SELECT data FROM subs ORDER BY pos ASC, id ASC", &out)
	return out, err
}

// GetSub returns a subscription by name.
func (s *Store) GetSub(name string) (map[string]any, error) {
	return s.queryMap("SELECT data FROM subs WHERE name = ?", name)
}

// UpsertSub inserts or updates a subscription.
func (s *Store) UpsertSub(name string, data map[string]any, position string) error {
	return s.upsertMap("subs", name, data, position)
}

// RenameSub renames a subscription in place, preserving its position.
func (s *Store) RenameSub(oldName, newName string, data map[string]any) error {
	return s.renameEntity("subs", oldName, newName, data)
}

// DeleteSub removes a subscription.
func (s *Store) DeleteSub(name string) error {
	return deleteEntity(s, "subs", name)
}

// RenameSubTx is the transaction-scoped variant of RenameSub.
func RenameSubTx(tx *sql.Tx, oldName, newName string, data map[string]any) error {
	return renameEntityTx(tx, "subs", oldName, newName, data)
}

// DeleteSubTx is the transaction-scoped variant of DeleteSub.
func DeleteSubTx(tx *sql.Tx, name string) error {
	return deleteEntityTx(tx, "subs", name)
}

// ---- collections ----

func (s *Store) ListCollections() ([]map[string]any, error) {
	out := []map[string]any{}
	err := s.queryMaps("SELECT data FROM collections ORDER BY pos ASC, id ASC", &out)
	return out, err
}

func (s *Store) GetCollection(name string) (map[string]any, error) {
	return s.queryMap("SELECT data FROM collections WHERE name = ?", name)
}

func (s *Store) UpsertCollection(name string, data map[string]any, position string) error {
	return s.upsertMap("collections", name, data, position)
}

// RenameCollection renames a collection in place, preserving its position.
func (s *Store) RenameCollection(oldName, newName string, data map[string]any) error {
	return s.renameEntity("collections", oldName, newName, data)
}

func (s *Store) DeleteCollection(name string) error {
	return deleteEntity(s, "collections", name)
}

// ListCollectionsTx is the transaction-scoped variant of ListCollections.
func ListCollectionsTx(tx *sql.Tx) ([]map[string]any, error) {
	return listMapsTx(tx, "SELECT data FROM collections ORDER BY pos ASC, id ASC")
}

// UpsertCollectionTx is the transaction-scoped variant of UpsertCollection.
func UpsertCollectionTx(tx *sql.Tx, name string, data map[string]any, position string) error {
	return upsertEntityTx(tx, "collections", name, data, position)
}

// ---- files ----

// ListFiles returns all stored files.
func (s *Store) ListFiles() ([]map[string]any, error) {
	out := []map[string]any{}
	err := s.queryMaps("SELECT data FROM files ORDER BY pos ASC, id ASC", &out)
	return out, err
}

// GetFile returns a file by name.
func (s *Store) GetFile(name string) (map[string]any, error) {
	return s.queryMap("SELECT data FROM files WHERE name = ?", name)
}

// UpsertFile inserts or updates a file.
func (s *Store) UpsertFile(name string, data map[string]any, position string) error {
	return s.upsertMap("files", name, data, position)
}

// RenameFile renames a file in place, preserving its position.
func (s *Store) RenameFile(oldName, newName string, data map[string]any) error {
	return s.renameEntity("files", oldName, newName, data)
}

// DeleteFile removes a file.
func (s *Store) DeleteFile(name string) error {
	return deleteEntity(s, "files", name)
}

// ---- tokens ----

func (s *Store) ListTokens() ([]map[string]any, error) {
	out := []map[string]any{}
	err := s.queryMaps("SELECT data FROM tokens ORDER BY id ASC", &out)
	return out, err
}

func (s *Store) GetToken(token string) (map[string]any, error) {
	return s.queryMap("SELECT data FROM tokens WHERE token = ?", token)
}

func (s *Store) InsertToken(data map[string]any) error {
	b, err := json.Marshal(data)
	if err != nil {
		return err
	}
	token, _ := data["token"].(string)
	_, err = s.db.Exec("INSERT INTO tokens (token, data) VALUES (?, ?)", token, string(b))
	if isUniqueViolation(err) {
		return fmt.Errorf("%w: token already exists", ErrNameConflict)
	}
	return err
}

func (s *Store) UpdateToken(data map[string]any) error {
	b, err := json.Marshal(data)
	if err != nil {
		return err
	}
	token, _ := data["token"].(string)
	_, err = s.db.Exec("UPDATE tokens SET data = ? WHERE token = ?", string(b), token)
	return err
}

func (s *Store) DeleteToken(token string) error {
	_, err := s.db.Exec("DELETE FROM tokens WHERE token = ?", token)
	return err
}

// ---- settings ----

func (s *Store) GetSettings() (map[string]any, error) {
	return s.queryMap("SELECT value FROM settings WHERE key = 'settings'", "")
}

func (s *Store) SaveSettings(v map[string]any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(
		"INSERT INTO settings (key, value) VALUES ('settings', ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
		string(b),
	)
	return err
}
