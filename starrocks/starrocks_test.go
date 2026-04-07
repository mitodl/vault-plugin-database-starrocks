package starrocks

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	dbplugin "github.com/hashicorp/vault/sdk/database/dbplugin/v5"
	"github.com/hashicorp/vault/sdk/database/helper/connutil"
	sdktemplate "github.com/hashicorp/vault/sdk/helper/template"
)

// ---------------------------------------------------------------------------
// Mock SQL driver
//
// mockDriver implements driver.Driver and driver.ExecerContext so that
// db.ExecContext calls use the COM_QUERY path and never COM_STMT_PREPARE.
// Calling Prepare on the mock panics — any accidental Prepare call causes an
// immediate, obvious test failure that mirrors the real StarRocks behaviour.
// ---------------------------------------------------------------------------

const mockDriverName = "starrocks-mock"

var (
	mockMu    sync.Mutex
	mockCalls []string
)

func init() {
	sql.Register(mockDriverName, &mockDriver{})
}

func resetMock() {
	mockMu.Lock()
	defer mockMu.Unlock()
	mockCalls = nil
}

func getMockCalls() []string {
	mockMu.Lock()
	defer mockMu.Unlock()
	return append([]string{}, mockCalls...)
}

type mockDriver struct{}

func (d *mockDriver) Open(_ string) (driver.Conn, error) {
	return &mockConn{}, nil
}

type mockConn struct{}

// Prepare panics to simulate StarRocks rejecting COM_STMT_PREPARE for DDL.
func (c *mockConn) Prepare(query string) (driver.Stmt, error) {
	panic(fmt.Sprintf("Prepare must not be called on StarRocks DDL: %q", query))
}

func (c *mockConn) Close() error { return nil }

func (c *mockConn) Begin() (driver.Tx, error) { return &mockTx{}, nil }

// ExecContext implements driver.ExecerContext.  database/sql calls this for
// parameterless Exec without going through Prepare.
func (c *mockConn) ExecContext(_ context.Context, query string, _ []driver.NamedValue) (driver.Result, error) {
	mockMu.Lock()
	defer mockMu.Unlock()
	mockCalls = append(mockCalls, query)
	return driver.RowsAffected(1), nil
}

type mockTx struct{}

func (t *mockTx) Commit() error   { return nil }
func (t *mockTx) Rollback() error { return nil }

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// newTestPlugin returns a StarRocks wired to the mock SQL driver.
// It pre-sets all required SQLConnectionProducer fields so that tests do not
// need a real database for unit-level assertions.
func newTestPlugin(t *testing.T) *StarRocks {
	t.Helper()
	up, err := sdktemplate.NewTemplate(sdktemplate.Template(defaultUsernameTemplate))
	if err != nil {
		t.Fatalf("creating username template: %v", err)
	}
	sr := &StarRocks{
		SQLConnectionProducer: &connutil.SQLConnectionProducer{
			ConnectionURL: "mock:mock@tcp(127.0.0.1:9030)/",
			Username:      "mock",
			Password:      "mock",
			Initialized:   true,
		},
		usernameProducer: up,
	}
	sr.SQLConnectionProducer.Type = mockDriverName
	return sr
}

func usernameConfig() dbplugin.UsernameMetadata {
	return dbplugin.UsernameMetadata{DisplayName: "testDisplay", RoleName: "testRole"}
}

// ---------------------------------------------------------------------------
// Tests: Type
// ---------------------------------------------------------------------------

func TestType(t *testing.T) {
	sr := newTestPlugin(t)
	got, err := sr.Type()
	if err != nil {
		t.Fatalf("Type() error: %v", err)
	}
	if got != typeName {
		t.Fatalf("Type() = %q, want %q", got, typeName)
	}
}

// ---------------------------------------------------------------------------
// Tests: New
// ---------------------------------------------------------------------------

func TestNew_ReturnsDatabase(t *testing.T) {
	iface, err := New()
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	if iface == nil {
		t.Fatal("New() returned nil")
	}
	if _, ok := iface.(dbplugin.Database); !ok {
		t.Fatal("New() does not implement dbplugin.Database")
	}
}

// ---------------------------------------------------------------------------
// Tests: Initialize
// ---------------------------------------------------------------------------

func newUninitializedPlugin(t *testing.T) *StarRocks {
	t.Helper()
	sr := &StarRocks{
		SQLConnectionProducer: &connutil.SQLConnectionProducer{},
	}
	sr.SQLConnectionProducer.Type = mockDriverName
	return sr
}

func baseInitConfig() map[string]interface{} {
	return map[string]interface{}{
		"connection_url": "mock:mock@tcp(127.0.0.1:9030)/",
		"username":       "mock",
		"password":       "mock",
	}
}

func TestInitialize_Success(t *testing.T) {
	sr := newUninitializedPlugin(t)
	resp, err := sr.Initialize(context.Background(), dbplugin.InitializeRequest{
		Config:           baseInitConfig(),
		VerifyConnection: false,
	})
	if err != nil {
		t.Fatalf("Initialize() error: %v", err)
	}
	if resp.Config == nil {
		t.Fatal("Initialize() returned nil Config")
	}
	// usernameProducer must be ready to generate a name
	_, err = sr.usernameProducer.Generate(usernameConfig())
	if err != nil {
		t.Fatalf("usernameProducer.Generate() after Initialize: %v", err)
	}
}

func TestInitialize_CustomTemplate(t *testing.T) {
	sr := newUninitializedPlugin(t)
	cfg := baseInitConfig()
	cfg["username_template"] = `{{ printf "u-%s" (random 8) | truncate 12 }}`

	if _, err := sr.Initialize(context.Background(), dbplugin.InitializeRequest{
		Config:           cfg,
		VerifyConnection: false,
	}); err != nil {
		t.Fatalf("Initialize() with custom template error: %v", err)
	}

	username, err := sr.usernameProducer.Generate(usernameConfig())
	if err != nil {
		t.Fatalf("Generate() with custom template: %v", err)
	}
	if !strings.HasPrefix(username, "u-") {
		t.Errorf("custom template username %q should start with 'u-'", username)
	}
	if len(username) > 12 {
		t.Errorf("custom template username %q exceeds 12 chars", username)
	}
}

func TestInitialize_InvalidTemplate(t *testing.T) {
	sr := newUninitializedPlugin(t)
	cfg := baseInitConfig()
	cfg["username_template"] = `{{ unclosed`

	if _, err := sr.Initialize(context.Background(), dbplugin.InitializeRequest{
		Config:           cfg,
		VerifyConnection: false,
	}); err == nil {
		t.Fatal("Initialize() with invalid template should return error")
	}
}

func TestInitialize_MissingConnectionURL(t *testing.T) {
	sr := newUninitializedPlugin(t)
	if _, err := sr.Initialize(context.Background(), dbplugin.InitializeRequest{
		Config:           map[string]interface{}{"username": "u", "password": "p"},
		VerifyConnection: false,
	}); err == nil {
		t.Fatal("Initialize() without connection_url should return error")
	}
}

// ---------------------------------------------------------------------------
// Tests: NewUser
// ---------------------------------------------------------------------------

func TestNewUser_EmptyStatements_Error(t *testing.T) {
	sr := newTestPlugin(t)
	req := dbplugin.NewUserRequest{
		UsernameConfig: usernameConfig(),
		Statements:     dbplugin.Statements{},
		Password:       "hunter2",
		Expiration:     time.Now().Add(time.Hour),
	}
	if _, err := sr.NewUser(context.Background(), req); err == nil {
		t.Fatal("NewUser() with empty statements should return error")
	}
}

func TestNewUser_UsesExecNotPrepare(t *testing.T) {
	resetMock()
	sr := newTestPlugin(t)

	// If Prepare were called the mock panics and the test fails.
	req := dbplugin.NewUserRequest{
		UsernameConfig: usernameConfig(),
		Statements: dbplugin.Statements{
			Commands: []string{`CREATE USER IF NOT EXISTS '{{name}}'@'%' IDENTIFIED BY '{{password}}';`},
		},
		Password:   "pw",
		Expiration: time.Now().Add(time.Hour),
	}
	if _, err := sr.NewUser(context.Background(), req); err != nil {
		t.Fatalf("NewUser() error: %v", err)
	}

	if calls := getMockCalls(); len(calls) != 1 {
		t.Fatalf("expected 1 ExecContext call, got %d: %v", len(calls), calls)
	}
}

func TestNewUser_SubstitutesTemplateVariables(t *testing.T) {
	resetMock()
	sr := newTestPlugin(t)

	req := dbplugin.NewUserRequest{
		UsernameConfig: usernameConfig(),
		Statements: dbplugin.Statements{
			Commands: []string{`CREATE USER IF NOT EXISTS '{{name}}'@'%' IDENTIFIED BY '{{password}}';`},
		},
		Password:   "s3cr3t!",
		Expiration: time.Now().Add(time.Hour),
	}
	resp, err := sr.NewUser(context.Background(), req)
	if err != nil {
		t.Fatalf("NewUser() error: %v", err)
	}

	executed := getMockCalls()[0]
	if strings.Contains(executed, "{{name}}") || strings.Contains(executed, "{{password}}") {
		t.Errorf("executed SQL still has template variables: %q", executed)
	}
	if !strings.Contains(executed, resp.Username) {
		t.Errorf("executed SQL %q missing generated username %q", executed, resp.Username)
	}
	if !strings.Contains(executed, "s3cr3t!") {
		t.Errorf("executed SQL %q missing password", executed)
	}
}

func TestNewUser_MultipleStatements(t *testing.T) {
	resetMock()
	sr := newTestPlugin(t)

	req := dbplugin.NewUserRequest{
		UsernameConfig: usernameConfig(),
		Statements: dbplugin.Statements{
			Commands: []string{
				`CREATE USER IF NOT EXISTS '{{name}}'@'%' IDENTIFIED BY '{{password}}';`,
				`GRANT SELECT ON ALL TABLES IN ALL DATABASES TO USER '{{name}}'@'%';`,
			},
		},
		Password:   "pw",
		Expiration: time.Now().Add(time.Hour),
	}
	if _, err := sr.NewUser(context.Background(), req); err != nil {
		t.Fatalf("NewUser() error: %v", err)
	}
	if calls := getMockCalls(); len(calls) != 2 {
		t.Fatalf("expected 2 ExecContext calls, got %d: %v", len(calls), calls)
	}
}

func TestNewUser_UsernameMatchesTemplate(t *testing.T) {
	sr := newTestPlugin(t)
	req := dbplugin.NewUserRequest{
		UsernameConfig: dbplugin.UsernameMetadata{
			DisplayName: "my-display-name",
			RoleName:    "readonly",
		},
		Statements: dbplugin.Statements{
			Commands: []string{`CREATE USER '{{name}}'@'%' IDENTIFIED BY '{{password}}';`},
		},
		Password:   "pw",
		Expiration: time.Now().Add(time.Hour),
	}
	resp, err := sr.NewUser(context.Background(), req)
	if err != nil {
		t.Fatalf("NewUser() error: %v", err)
	}
	if !strings.HasPrefix(resp.Username, "v-") {
		t.Errorf("username %q does not start with 'v-'", resp.Username)
	}
	if len(resp.Username) > 32 {
		t.Errorf("username %q exceeds 32 chars (len=%d)", resp.Username, len(resp.Username))
	}
}

func TestNewUser_ReturnsNonEmptyUsername(t *testing.T) {
	sr := newTestPlugin(t)
	req := dbplugin.NewUserRequest{
		UsernameConfig: usernameConfig(),
		Statements:     dbplugin.Statements{Commands: []string{`CREATE USER '{{name}}'@'%' IDENTIFIED BY '{{password}}';`}},
		Password:       "pw",
		Expiration:     time.Now().Add(time.Hour),
	}
	resp, err := sr.NewUser(context.Background(), req)
	if err != nil {
		t.Fatalf("NewUser() error: %v", err)
	}
	if resp.Username == "" {
		t.Fatal("NewUser() returned empty username")
	}
}

// ---------------------------------------------------------------------------
// Tests: UpdateUser
// ---------------------------------------------------------------------------

func TestUpdateUser_NilPassword_IsNoOp(t *testing.T) {
	resetMock()
	sr := newTestPlugin(t)
	if _, err := sr.UpdateUser(context.Background(), dbplugin.UpdateUserRequest{
		Username: "existing",
		Password: nil,
	}); err != nil {
		t.Fatalf("UpdateUser() with nil password should be no-op, got: %v", err)
	}
	if calls := getMockCalls(); len(calls) != 0 {
		t.Fatalf("UpdateUser() with nil password should not execute statements, got: %v", calls)
	}
}

func TestUpdateUser_DefaultRotationStatement(t *testing.T) {
	resetMock()
	sr := newTestPlugin(t)
	if _, err := sr.UpdateUser(context.Background(), dbplugin.UpdateUserRequest{
		Username: "existing",
		Password: &dbplugin.ChangePassword{
			NewPassword: "newpw",
			Statements:  dbplugin.Statements{}, // empty → default rotation
		},
	}); err != nil {
		t.Fatalf("UpdateUser() error: %v", err)
	}

	calls := getMockCalls()
	if len(calls) != 1 {
		t.Fatalf("expected 1 call, got %d: %v", len(calls), calls)
	}
	if !strings.Contains(calls[0], "ALTER USER") {
		t.Errorf("default rotation should use ALTER USER, got: %q", calls[0])
	}
	if !strings.Contains(calls[0], "existing") {
		t.Errorf("rotation statement missing username: %q", calls[0])
	}
	if !strings.Contains(calls[0], "newpw") {
		t.Errorf("rotation statement missing new password: %q", calls[0])
	}
}

func TestUpdateUser_CustomStatements(t *testing.T) {
	resetMock()
	sr := newTestPlugin(t)
	custom := `ALTER USER '{{username}}'@'127.0.0.1' IDENTIFIED BY '{{password}}';`
	if _, err := sr.UpdateUser(context.Background(), dbplugin.UpdateUserRequest{
		Username: "existing",
		Password: &dbplugin.ChangePassword{
			NewPassword: "newpw",
			Statements:  dbplugin.Statements{Commands: []string{custom}},
		},
	}); err != nil {
		t.Fatalf("UpdateUser() error: %v", err)
	}
	executed := getMockCalls()[0]
	if strings.Contains(executed, "{{username}}") || strings.Contains(executed, "{{password}}") {
		t.Errorf("custom rotation has unsubstituted variables: %q", executed)
	}
}

func TestUpdateUser_UsesExecNotPrepare(t *testing.T) {
	// Prepare panics in mock; reaching end of test without panic is the assertion.
	sr := newTestPlugin(t)
	if _, err := sr.UpdateUser(context.Background(), dbplugin.UpdateUserRequest{
		Username: "u",
		Password: &dbplugin.ChangePassword{NewPassword: "p", Statements: dbplugin.Statements{}},
	}); err != nil {
		t.Fatalf("UpdateUser() error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Tests: DeleteUser
// ---------------------------------------------------------------------------

func TestDeleteUser_DefaultRevocationStatement(t *testing.T) {
	resetMock()
	sr := newTestPlugin(t)
	if _, err := sr.DeleteUser(context.Background(), dbplugin.DeleteUserRequest{
		Username:   "v-test-user",
		Statements: dbplugin.Statements{}, // empty → default DROP USER
	}); err != nil {
		t.Fatalf("DeleteUser() error: %v", err)
	}

	calls := getMockCalls()
	if len(calls) != 1 {
		t.Fatalf("expected 1 call, got %d: %v", len(calls), calls)
	}
	if !strings.Contains(calls[0], "DROP USER") {
		t.Errorf("default revocation should use DROP USER, got: %q", calls[0])
	}
	if !strings.Contains(calls[0], "v-test-user") {
		t.Errorf("revocation statement missing username: %q", calls[0])
	}
}

func TestDeleteUser_CustomStatements(t *testing.T) {
	resetMock()
	sr := newTestPlugin(t)
	custom := `DROP USER IF EXISTS '{{name}}'@'%';`
	if _, err := sr.DeleteUser(context.Background(), dbplugin.DeleteUserRequest{
		Username:   "v-test-user",
		Statements: dbplugin.Statements{Commands: []string{custom}},
	}); err != nil {
		t.Fatalf("DeleteUser() error: %v", err)
	}
	executed := getMockCalls()[0]
	if strings.Contains(executed, "{{name}}") {
		t.Errorf("revocation statement has unsubstituted variables: %q", executed)
	}
	if !strings.Contains(executed, "v-test-user") {
		t.Errorf("revocation statement missing username: %q", executed)
	}
}

func TestDeleteUser_UsesExecNotPrepare(t *testing.T) {
	// Prepare panics in mock; reaching end is the assertion.
	sr := newTestPlugin(t)
	if _, err := sr.DeleteUser(context.Background(), dbplugin.DeleteUserRequest{
		Username:   "u",
		Statements: dbplugin.Statements{},
	}); err != nil {
		t.Fatalf("DeleteUser() error: %v", err)
	}
}

func TestDeleteUser_EmptyCommandSlice_UsesDefault(t *testing.T) {
	resetMock()
	sr := newTestPlugin(t)
	if _, err := sr.DeleteUser(context.Background(), dbplugin.DeleteUserRequest{
		Username:   "myuser",
		Statements: dbplugin.Statements{Commands: []string{}},
	}); err != nil {
		t.Fatalf("DeleteUser() error: %v", err)
	}
	calls := getMockCalls()
	if len(calls) != 1 {
		t.Fatalf("expected 1 call, got %d", len(calls))
	}
	if !strings.Contains(calls[0], "DROP USER") {
		t.Errorf("empty command slice should use default DROP USER: %q", calls[0])
	}
}

// ---------------------------------------------------------------------------
// Tests: Close
// ---------------------------------------------------------------------------

func TestClose_WithNoConnection(t *testing.T) {
	sr := newTestPlugin(t)
	if err := sr.Close(); err != nil {
		t.Fatalf("Close() error: %v", err)
	}
}
