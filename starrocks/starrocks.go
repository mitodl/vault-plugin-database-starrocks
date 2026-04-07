// Package starrocks implements a Vault database plugin for StarRocks.
//
// StarRocks exposes a MySQL-compatible wire protocol but only supports the
// COM_STMT_PREPARE binary protocol for SELECT statements. All DDL and privilege
// management statements (CREATE USER, GRANT, DROP USER, ALTER USER) return
// error 1295: "This command is not supported in the prepared statement protocol
// yet".
//
// Vault's built-in MySQL plugin sends every creation/revocation statement via
// COM_STMT_PREPARE, which panics with a nil pointer dereference when StarRocks
// rejects the prepare. This plugin replaces that code path with db.ExecContext
// (no parameters), which sends COM_QUERY instead and works for all statement
// types that StarRocks supports.
package starrocks

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"sync"

	_ "github.com/go-sql-driver/mysql"
	dbplugin "github.com/hashicorp/vault/sdk/database/dbplugin/v5"
	"github.com/hashicorp/vault/sdk/database/helper/connutil"
	"github.com/hashicorp/vault/sdk/database/helper/dbutil"
	sdktemplate "github.com/hashicorp/vault/sdk/helper/template"
)

const (
	typeName = "starrocks"

	// defaultUsernameTemplate matches the format used by Vault's built-in MySQL
	// plugin and fits within StarRocks's 64-character username limit.
	defaultUsernameTemplate = `{{ printf "v-%.8s-%.8s-%.20s" (.DisplayName | truncate 8) (.RoleName | truncate 8) (random 20) | truncate 32 }}`

	// defaultRevocationStatement is used when no revocation statements are
	// configured for a role.
	defaultRevocationStatement = `DROP USER IF EXISTS '{{name}}'@'%';`

	// defaultRotationStatement rotates the password for an existing user.
	defaultRotationStatement = `ALTER USER '{{username}}'@'%' IDENTIFIED BY '{{password}}';`
)

// StarRocks implements dbplugin.Database for the StarRocks analytics database.
type StarRocks struct {
	*connutil.SQLConnectionProducer

	usernameProducer sdktemplate.StringTemplate

	mu sync.RWMutex
}

// New returns a new StarRocks plugin instance wrapped in error-sanitizing
// middleware. The return type is interface{} to satisfy dbplugin.Factory.
func New() (interface{}, error) {
	db := &StarRocks{
		SQLConnectionProducer: &connutil.SQLConnectionProducer{},
	}
	// SQLConnectionProducer.Type is the SQL driver name (not the Vault catalog
	// name). StarRocks uses the MySQL wire protocol, so we use the "mysql"
	// driver registered by go-sql-driver/mysql. The Vault catalog name is
	// returned separately by the Type() method below.
	db.SQLConnectionProducer.Type = "mysql"
	return dbplugin.NewDatabaseErrorSanitizerMiddleware(db, db.secretValues), nil
}

func (s *StarRocks) secretValues() map[string]string {
	return map[string]string{
		s.Password: "[password]",
	}
}

// Type returns the plugin type name used in Vault's database catalog.
func (s *StarRocks) Type() (string, error) {
	return typeName, nil
}

// Initialize configures the plugin from the supplied config map and optionally
// verifies the connection to StarRocks.
func (s *StarRocks) Initialize(ctx context.Context, req dbplugin.InitializeRequest) (dbplugin.InitializeResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	newConf, err := s.SQLConnectionProducer.Init(ctx, req.Config, req.VerifyConnection)
	if err != nil {
		return dbplugin.InitializeResponse{}, fmt.Errorf("initializing connection: %w", err)
	}

	usernameTemplate, err := getString(req.Config, "username_template", defaultUsernameTemplate)
	if err != nil {
		return dbplugin.InitializeResponse{}, fmt.Errorf("reading username_template: %w", err)
	}

	up, err := sdktemplate.NewTemplate(sdktemplate.Template(usernameTemplate))
	if err != nil {
		return dbplugin.InitializeResponse{}, fmt.Errorf("parsing username_template: %w", err)
	}
	s.usernameProducer = up

	return dbplugin.InitializeResponse{Config: newConf}, nil
}

// NewUser creates a StarRocks user from the role's creation statements.
//
// Each statement has {{name}} and {{password}} substituted, then is sent to
// StarRocks via COM_QUERY (db.ExecContext with no parameters). This bypasses
// the COM_STMT_PREPARE path that StarRocks does not support for DDL.
func (s *StarRocks) NewUser(ctx context.Context, req dbplugin.NewUserRequest) (dbplugin.NewUserResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if len(req.Statements.Commands) == 0 {
		return dbplugin.NewUserResponse{}, dbutil.ErrEmptyCreationStatement
	}

	username, err := s.usernameProducer.Generate(req.UsernameConfig)
	if err != nil {
		return dbplugin.NewUserResponse{}, fmt.Errorf("generating username: %w", err)
	}

	queryMap := map[string]string{
		"name":       username,
		"username":   username,
		"password":   req.Password,
		"expiration": req.Expiration.Format("2006-01-02 15:04:05-0700"),
	}

	if err := s.executeStatements(ctx, req.Statements.Commands, queryMap); err != nil {
		return dbplugin.NewUserResponse{}, err
	}

	return dbplugin.NewUserResponse{Username: username}, nil
}

// UpdateUser rotates the password for an existing StarRocks user.
func (s *StarRocks) UpdateUser(ctx context.Context, req dbplugin.UpdateUserRequest) (dbplugin.UpdateUserResponse, error) {
	if req.Password == nil {
		return dbplugin.UpdateUserResponse{}, nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	stmts := req.Password.Statements.Commands
	if len(stmts) == 0 {
		stmts = []string{defaultRotationStatement}
	}

	queryMap := map[string]string{
		"name":     req.Username,
		"username": req.Username,
		"password": req.Password.NewPassword,
	}

	if err := s.executeStatements(ctx, stmts, queryMap); err != nil {
		return dbplugin.UpdateUserResponse{}, err
	}

	return dbplugin.UpdateUserResponse{}, nil
}

// DeleteUser drops a StarRocks user using the role's revocation statements.
func (s *StarRocks) DeleteUser(ctx context.Context, req dbplugin.DeleteUserRequest) (dbplugin.DeleteUserResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	stmts := req.Statements.Commands
	if len(stmts) == 0 {
		stmts = []string{defaultRevocationStatement}
	}

	queryMap := map[string]string{
		"name":     req.Username,
		"username": req.Username,
	}

	if err := s.executeStatements(ctx, stmts, queryMap); err != nil {
		return dbplugin.DeleteUserResponse{}, err
	}

	return dbplugin.DeleteUserResponse{}, nil
}

// executeStatements runs each statement against StarRocks using db.ExecContext
// (no bind parameters), which causes go-sql-driver to send COM_QUERY instead
// of COM_STMT_PREPARE. StarRocks supports COM_QUERY for all statement types
// that Vault needs (CREATE USER, GRANT, DROP USER, ALTER USER), but only
// supports COM_STMT_PREPARE for SELECT.
func (s *StarRocks) executeStatements(ctx context.Context, statements []string, queryMap map[string]string) error {
	db, err := s.getConnection(ctx)
	if err != nil {
		return err
	}

	for _, stmt := range statements {
		stmt = strings.TrimSpace(stmt)
		if stmt == "" {
			continue
		}
		parsed := dbutil.QueryHelper(stmt, queryMap)
		if _, err := db.ExecContext(ctx, parsed); err != nil {
			return fmt.Errorf("executing statement: %w", err)
		}
	}
	return nil
}

func (s *StarRocks) getConnection(ctx context.Context) (*sql.DB, error) {
	conn, err := s.Connection(ctx)
	if err != nil {
		return nil, err
	}
	db, ok := conn.(*sql.DB)
	if !ok {
		return nil, fmt.Errorf("unexpected connection type: %T", conn)
	}
	return db, nil
}

// getString extracts a string value from a config map, returning defaultVal if
// the key is absent or empty.
func getString(config map[string]interface{}, key, defaultVal string) (string, error) {
	val, ok := config[key]
	if !ok {
		return defaultVal, nil
	}
	s, ok := val.(string)
	if !ok {
		return "", fmt.Errorf("%q must be a string", key)
	}
	if s == "" {
		return defaultVal, nil
	}
	return s, nil
}
