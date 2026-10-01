// SPDX-License-Identifier: Apache-2.0

package postgres_test

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/peterldowns/pgtestdb"
	"github.com/pressly/goose/v3/lock"

	"github.com/gopherium/gouncer"
	"github.com/gopherium/gouncer/authkit/postgres"
	"github.com/gopherium/gouncer/authkit/postgres/testdb"
)

// freshDatabaseURL returns the URL of an empty, unmigrated test database.
func freshDatabaseURL(t *testing.T) string {
	t.Helper()
	if testing.Short() {
		t.Skip("skipping database test in short mode")
	}
	return pgtestdb.Custom(t, testdb.Config(), pgtestdb.NoopMigrator{}).URL()
}

func TestMigrateCreatesAuthSchema(t *testing.T) {
	t.Parallel()

	databaseURL := freshDatabaseURL(t)

	if err := postgres.Migrate(t.Context(), databaseURL); err != nil {
		t.Fatalf("Migrate() error = %v, want nil", err)
	}
	if err := postgres.Migrate(t.Context(), databaseURL); err != nil {
		t.Fatalf("second Migrate() error = %v, want idempotent nil", err)
	}

	db, err := sql.Open("pgx", databaseURL)
	if err != nil {
		t.Fatalf("opening database: %v", err)
	}
	defer func() { _ = db.Close() }()
	ada, err := gouncer.NewUser("ada@example.com", "Ada Lovelace", "correct horse battery")
	if err != nil {
		t.Fatalf("gouncer.NewUser() error = %v, want nil", err)
	}
	if _, err := db.Exec(
		"INSERT INTO auth.users (id, email, name, password_hash, disabled, confirmed, created_at)"+
			" VALUES ($1, $2, $3, $4, $5, $6, $7)",
		ada.ID, ada.Email, ada.Name, ada.PasswordHash, ada.Disabled, ada.Confirmed, ada.CreatedAt,
	); err != nil {
		t.Fatalf("inserting into migrated schema: %v", err)
	}
}

func TestMigrateUsesItsOwnVersionTable(t *testing.T) {
	t.Parallel()

	databaseURL := freshDatabaseURL(t)
	if err := postgres.Migrate(t.Context(), databaseURL); err != nil {
		t.Fatalf("Migrate() error = %v, want nil", err)
	}

	db, err := sql.Open("pgx", databaseURL)
	if err != nil {
		t.Fatalf("opening database: %v", err)
	}
	defer func() { _ = db.Close() }()
	var count int
	err = db.QueryRow(
		"SELECT count(*) FROM information_schema.tables WHERE table_schema = 'auth' AND table_name = 'goose_db_version'",
	).Scan(&count)

	if err != nil {
		t.Fatalf("looking up the version table: %v", err)
	}
	if count != 1 {
		t.Errorf("auth.goose_db_version tables = %d, want 1 (the module's own lineage)", count)
	}
}

// lockedDatabase returns a fresh database, a handle on it and a connection holding goose's migration lock.
func lockedDatabase(t *testing.T) (string, *sql.DB, *sql.Conn) {
	t.Helper()
	databaseURL := freshDatabaseURL(t)
	db, err := sql.Open("pgx", databaseURL)
	if err != nil {
		t.Fatalf("opening database: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	holder, err := db.Conn(t.Context())
	if err != nil {
		t.Fatalf("taking a connection: %v", err)
	}
	t.Cleanup(func() { _ = holder.Close() })
	if _, err := holder.ExecContext(t.Context(), "SELECT pg_advisory_lock($1)", lock.DefaultLockID); err != nil {
		t.Fatalf("holding the migration lock: %v", err)
	}
	return databaseURL, db, holder
}

// backendPID returns the Postgres process serving conn.
func backendPID(t *testing.T, conn *sql.Conn) int32 {
	t.Helper()
	var pid int32
	if err := conn.QueryRowContext(t.Context(), "SELECT pg_backend_pid()").Scan(&pid); err != nil {
		t.Fatalf("reading the connection's process: %v", err)
	}
	return pid
}

// awaitSession returns once a session of db other than holder has column like pattern, failing if ran ends first.
func awaitSession(t *testing.T, db *sql.DB, holder int32, ran <-chan error, column, pattern string) {
	t.Helper()
	lookup := "SELECT EXISTS (SELECT FROM pg_stat_activity WHERE datname = current_database()" +
		" AND pid NOT IN (pg_backend_pid(), $1) AND " + column + " LIKE $2)"
	for {
		var found bool
		if err := db.QueryRowContext(t.Context(), lookup, holder, pattern).Scan(&found); err != nil {
			t.Fatalf("looking for the session: %v", err)
		}
		if found {
			return
		}
		select {
		case err := <-ran:
			t.Fatalf("Migrate() = %v before a session had %s like %s", err, column, pattern)
		case <-time.After(10 * time.Millisecond):
		}
	}
}

func TestMigrateWaitsForTheMigrationLock(t *testing.T) {
	t.Parallel()

	databaseURL, db, _ := lockedDatabase(t)
	ctx, cancel := context.WithTimeout(t.Context(), 500*time.Millisecond)
	defer cancel()

	err := postgres.Migrate(ctx, databaseURL)

	var created bool
	if scanErr := db.QueryRow("SELECT to_regclass('auth.users') IS NOT NULL").Scan(&created); scanErr != nil {
		t.Fatalf("looking up the users table: %v", scanErr)
	}
	if !errors.Is(err, context.DeadlineExceeded) || created {
		t.Errorf("Migrate() = %v with the users table created %v, want the deadline and no migration", err, created)
	}
}

func TestMigrateSucceedsWhenAnotherSessionCreatesTheSchemaFirst(t *testing.T) {
	t.Parallel()

	databaseURL := freshDatabaseURL(t)
	db, err := sql.Open("pgx", databaseURL)
	if err != nil {
		t.Fatalf("opening database: %v", err)
	}
	defer func() { _ = db.Close() }()
	holder, err := db.Conn(t.Context())
	if err != nil {
		t.Fatalf("taking a connection: %v", err)
	}
	defer func() { _ = holder.Close() }()
	pid := backendPID(t, holder)
	tx, err := holder.BeginTx(t.Context(), nil)
	if err != nil {
		t.Fatalf("beginning: %v", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(t.Context(), "CREATE SCHEMA auth"); err != nil {
		t.Fatalf("creating the auth schema: %v", err)
	}
	ran := make(chan error, 1)
	go func() { ran <- postgres.Migrate(t.Context(), databaseURL) }()
	awaitSession(t, db, pid, ran, "wait_event_type", "Lock")

	if err := tx.Commit(); err != nil {
		t.Fatalf("committing the auth schema: %v", err)
	}

	if err := <-ran; err != nil {
		t.Errorf("Migrate() = %v, want it to succeed", err)
	}
}

func TestMigrateLetsAConcurrentIndexBuildFinishWhileItWaits(t *testing.T) {
	t.Parallel()

	databaseURL, db, holder := lockedDatabase(t)
	if _, err := holder.ExecContext(t.Context(), "CREATE TABLE items (x int)"); err != nil {
		t.Fatalf("creating the indexed table: %v", err)
	}
	ran := make(chan error, 1)
	go func() { ran <- postgres.Migrate(t.Context(), databaseURL) }()
	awaitSession(t, db, backendPID(t, holder), ran, "query", "%advisory%")

	_, built := holder.ExecContext(t.Context(), "CREATE INDEX CONCURRENTLY items_x ON items (x)")
	if _, err := holder.ExecContext(t.Context(), "SELECT pg_advisory_unlock($1)", lock.DefaultLockID); err != nil {
		t.Fatalf("releasing the migration lock: %v", err)
	}

	if err := <-ran; built != nil || err != nil {
		t.Errorf("index build = %v and Migrate() = %v, want both to finish", built, err)
	}
}

func TestMigrateNamesASchemaItCannotCreate(t *testing.T) {
	t.Parallel()

	databaseURL := freshDatabaseURL(t)
	db, err := sql.Open("pgx", databaseURL)
	if err != nil {
		t.Fatalf("opening database: %v", err)
	}
	defer func() { _ = db.Close() }()
	if _, err := db.Exec("DO $$ BEGIN EXECUTE format(" +
		"'ALTER DATABASE %I SET default_transaction_read_only = on', current_database()); END $$"); err != nil {
		t.Fatalf("making the database read only: %v", err)
	}

	err = postgres.Migrate(t.Context(), databaseURL)

	if err == nil || !strings.Contains(err.Error(), "create the auth schema: ") {
		t.Errorf("Migrate() = %v, want the auth schema named", err)
	}
}

func TestMigrateLetsRunsAtOnceAllSucceed(t *testing.T) {
	t.Parallel()

	databaseURL := freshDatabaseURL(t)
	failures := make(chan error, 4)
	var runs sync.WaitGroup
	for range 4 {
		runs.Go(func() {
			failures <- postgres.Migrate(t.Context(), databaseURL)
		})
	}
	runs.Wait()
	close(failures)

	for err := range failures {
		if err != nil {
			t.Errorf("Migrate() error = %v, want every run to succeed", err)
		}
	}
}

func TestMigrationsIndexSessionsExpiresAt(t *testing.T) {
	t.Parallel()

	db := newTestDB(t)

	var indexdef string
	err := db.QueryRow(
		"SELECT indexdef FROM pg_indexes WHERE schemaname = 'auth' AND indexname = 'sessions_expires_at_idx'",
	).Scan(&indexdef)

	if err != nil {
		t.Fatalf("looking up sessions_expires_at_idx: %v, want the index to exist", err)
	}
	if !strings.Contains(indexdef, "(expires_at)") {
		t.Errorf("indexdef = %q, want an index on (expires_at)", indexdef)
	}
}

func TestMigrationsIndexTokens(t *testing.T) {
	t.Parallel()

	db := newTestDB(t)

	for name, want := range map[string]string{
		"tokens_user_id_purpose_idx": "(user_id, purpose)",
		"tokens_expires_at_idx":      "(expires_at)",
	} {
		var indexdef string
		err := db.QueryRow(
			"SELECT indexdef FROM pg_indexes WHERE schemaname = 'auth' AND indexname = $1", name,
		).Scan(&indexdef)
		if err != nil {
			t.Errorf("looking up %s: %v, want the index to exist", name, err)
			continue
		}
		if !strings.Contains(indexdef, want) {
			t.Errorf("%s indexdef = %q, want an index on %s", name, indexdef, want)
		}
	}
}

func TestMigrationsCascadeTokensWithTheirAccount(t *testing.T) {
	t.Parallel()

	db := newTestDB(t)
	ada, err := gouncer.NewUser("ada@example.com", "Ada Lovelace", "correct horse battery")
	if err != nil {
		t.Fatalf("gouncer.NewUser() error = %v, want nil", err)
	}
	if _, err := db.Exec(
		"INSERT INTO auth.users (id, email, name, password_hash, disabled, confirmed, created_at)"+
			" VALUES ($1, $2, $3, $4, $5, $6, $7)",
		ada.ID, ada.Email, ada.Name, ada.PasswordHash, ada.Disabled, ada.Confirmed, ada.CreatedAt,
	); err != nil {
		t.Fatalf("inserting the account: %v", err)
	}
	tok, err := gouncer.NewToken(ada.ID, gouncer.PurposeInvite, time.Hour)
	if err != nil {
		t.Fatalf("gouncer.NewToken() error = %v, want nil", err)
	}
	if _, err := db.Exec(
		"INSERT INTO auth.tokens (token_hash, user_id, purpose, created_at, expires_at) VALUES ($1, $2, $3, $4, $5)",
		tok.TokenHash, tok.UserID, tok.Purpose, tok.CreatedAt, tok.ExpiresAt,
	); err != nil {
		t.Fatalf("inserting the token: %v", err)
	}

	if _, err := db.Exec("DELETE FROM auth.users WHERE id = $1", ada.ID); err != nil {
		t.Fatalf("deleting the account: %v", err)
	}

	var held int
	if err := db.QueryRow("SELECT count(*) FROM auth.tokens WHERE user_id = $1", ada.ID).Scan(&held); err != nil {
		t.Fatalf("counting the tokens left: %v", err)
	}
	if held != 0 {
		t.Errorf("tokens left after the account went = %d, want 0", held)
	}
}

func TestMigrationsConfirmTheAccountsAnOlderReleaseInserts(t *testing.T) {
	t.Parallel()

	db := newTestDB(t)
	ada, err := gouncer.NewUser("ada@example.com", "Ada Lovelace", "correct horse battery")
	if err != nil {
		t.Fatalf("gouncer.NewUser() error = %v, want nil", err)
	}

	_, err = db.Exec(
		"INSERT INTO auth.users (id, email, name, password_hash, disabled, created_at) VALUES ($1, $2, $3, $4, $5, $6)",
		ada.ID, ada.Email, ada.Name, ada.PasswordHash, ada.Disabled, ada.CreatedAt,
	)

	if err != nil {
		t.Fatalf("inserting the way a release before this one does: %v", err)
	}
	var confirmed bool
	if err := db.QueryRow("SELECT confirmed FROM auth.users WHERE id = $1", ada.ID).Scan(&confirmed); err != nil {
		t.Fatalf("reading the confirmation back: %v", err)
	}
	if !confirmed {
		t.Error("confirmed = false, want an account an older release inserts to count as activated")
	}
}

func TestMigrateRejectsMalformedURL(t *testing.T) {
	t.Parallel()

	if err := postgres.Migrate(t.Context(), "://not-a-url"); err == nil {
		t.Fatal("Migrate() error = nil, want a parse error")
	}
}

func TestMigrateReportsUnreachableDatabase(t *testing.T) {
	t.Parallel()

	err := postgres.Migrate(
		t.Context(),
		"postgres://postgres:postgres@localhost:9/postgres?sslmode=disable&connect_timeout=1",
	)

	if err == nil {
		t.Fatal("Migrate() error = nil, want a connection error")
	}
}

func TestMigrateReportsFailedMigrations(t *testing.T) {
	t.Parallel()

	databaseURL := freshDatabaseURL(t)
	db, err := sql.Open("pgx", databaseURL)
	if err != nil {
		t.Fatalf("opening database: %v", err)
	}
	defer func() { _ = db.Close() }()
	if _, err := db.Exec("CREATE SCHEMA auth; CREATE TABLE auth.users (id int)"); err != nil {
		t.Fatalf("planting the conflicting table: %v", err)
	}

	if err := postgres.Migrate(t.Context(), databaseURL); err == nil {
		t.Fatal("Migrate() error = nil, want a failed migration")
	}
}
