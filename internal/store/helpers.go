package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"modernc.org/sqlite"
)

// ErrNameConflict signals that a write failed because a UNIQUE constraint
// was violated (e.g. renaming to a name that already exists). Server
// handlers map it to HTTP 409 instead of a generic 500.
var ErrNameConflict = errors.New("name conflict")

// isUniqueViolation reports whether err is (or wraps) a SQLite UNIQUE
// constraint violation. Handles both base (19) and extended result codes.
func isUniqueViolation(err error) bool {
	if err == nil {
		return false
	}
	var serr *sqlite.Error
	if errors.As(err, &serr) {
		code := serr.Code()
		primary := code
		if code > 0xff {
			primary = code >> 8
		}
		if primary == 19 { // SQLITE_CONSTRAINT
			return true
		}
	}
	return strings.Contains(err.Error(), "UNIQUE constraint failed")
}

// queryMap scans a single JSON column row into a map.
func (s *Store) queryMap(query string, arg any) (map[string]any, error) {
	var raw string
	var err error
	if arg != nil {
		err = s.db.QueryRow(query, arg).Scan(&raw)
	} else {
		err = s.db.QueryRow(query).Scan(&raw)
	}
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		return nil, err
	}
	if m == nil {
		m = map[string]any{}
	}
	return m, nil
}

// queryMaps scans all rows of a single JSON column into a list of maps.
func (s *Store) queryMaps(query string, dest *[]map[string]any) error {
	rows, err := s.db.Query(query)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var raw string
		if err := rows.Scan(&raw); err != nil {
			return err
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(raw), &m); err != nil {
			return err
		}
		if m == nil {
			m = map[string]any{}
		}
		*dest = append(*dest, m)
	}
	return rows.Err()
}

// upsertMap inserts or updates a row in a name-keyed table.
func (s *Store) upsertMap(table, name string, data map[string]any, position string) error {
	b, err := json.Marshal(data)
	if err != nil {
		return err
	}
	pos := 0
	if position == "top" {
		err = s.db.QueryRow(fmt.Sprintf("SELECT COALESCE(MIN(pos), 1) - 1 FROM %s", table)).Scan(&pos)
	} else {
		err = s.db.QueryRow(fmt.Sprintf("SELECT COALESCE(MAX(pos), 0) + 1 FROM %s", table)).Scan(&pos)
	}
	if err != nil {
		return err
	}
	_, err = s.db.Exec(
		fmt.Sprintf("INSERT INTO %s (name, data, pos) VALUES (?, ?, ?) ON CONFLICT(name) DO UPDATE SET data = excluded.data", table),
		name, string(b), pos,
	)
	return err
}

// renameEntity renames a row in place, keeping its position. This mirrors
// Sub-Store's updateByName semantics: renaming an item must not move it to
// the bottom of the list. A UNIQUE violation is reported as ErrNameConflict.
func (s *Store) renameEntity(table, oldName, newName string, data map[string]any) error {
	return renameEntityTx(s.db, table, oldName, newName, data)
}

// ---- transaction-scoped generic helpers ----

// dbtx is satisfied by both *sql.DB and *sql.Tx, letting the generic
// helpers run either standalone or inside a transaction.
type dbtx interface {
	Exec(query string, args ...any) (sql.Result, error)
	QueryRow(query string, args ...any) *sql.Row
	Query(query string, args ...any) (*sql.Rows, error)
}

// listMapsTx scans all rows of a single JSON column within tx.
func listMapsTx(tx dbtx, query string) ([]map[string]any, error) {
	rows, err := tx.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var raw string
		if err := rows.Scan(&raw); err != nil {
			return nil, err
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(raw), &m); err != nil {
			return nil, err
		}
		if m == nil {
			m = map[string]any{}
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// upsertEntityTx is the transaction-scoped variant of upsertEntity.
func upsertEntityTx(tx dbtx, table, name string, item map[string]any, position string) error {
	data, err := json.Marshal(item)
	if err != nil {
		return err
	}
	var pos int
	if position == "top" {
		err = tx.QueryRow(fmt.Sprintf("SELECT COALESCE(MIN(pos), 1) - 1 FROM %s", table)).Scan(&pos)
	} else {
		err = tx.QueryRow(fmt.Sprintf("SELECT COALESCE(MAX(pos), 0) + 1 FROM %s", table)).Scan(&pos)
	}
	if err != nil {
		return err
	}
	_, err = tx.Exec(
		fmt.Sprintf("INSERT INTO %s (name, data, pos) VALUES (?, ?, ?) ON CONFLICT(name) DO UPDATE SET data = excluded.data", table),
		name, string(data), pos,
	)
	return err
}

// renameEntityTx is the transaction-scoped variant of renameEntity. A UNIQUE
// violation is reported as ErrNameConflict.
func renameEntityTx(tx dbtx, table, oldName, newName string, data map[string]any) error {
	b, err := json.Marshal(data)
	if err != nil {
		return err
	}
	_, err = tx.Exec(
		fmt.Sprintf("UPDATE %s SET name = ?, data = ? WHERE name = ?", table),
		newName, string(b), oldName,
	)
	if isUniqueViolation(err) {
		return fmt.Errorf("%w: %s -> %s", ErrNameConflict, oldName, newName)
	}
	return err
}

// deleteEntityTx is the transaction-scoped variant of deleteEntity.
func deleteEntityTx(tx dbtx, table, name string) error {
	_, err := tx.Exec(fmt.Sprintf("DELETE FROM %s WHERE name = ?", table), name)
	return err
}
