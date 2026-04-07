# vault-plugin-database-starrocks

A custom [Vault database secrets engine][vault-db] plugin for [StarRocks][starrocks].

## Why does this exist?

Vault's built-in MySQL plugin (`mysql-database-plugin` and its variants) uses the
MySQL binary protocol (`COM_STMT_PREPARE` / `COM_STMT_EXECUTE`) for every creation,
revocation, and rotation statement.

StarRocks speaks the MySQL wire protocol but only supports `COM_STMT_PREPARE` for
`SELECT` statements. All DDL and privilege management statements (`CREATE USER`,
`GRANT`, `DROP USER`, `ALTER USER`) return:

```
Error 1295: This command is not supported in the prepared statement protocol yet
```

Because `dbutil.QueryHelper` pre-substitutes `{{name}}` / `{{password}}` template
variables before the SQL is sent to the database—leaving no `?` placeholders—the
SQL can safely be sent via `db.ExecContext` with no bind parameters. The Go
`database/sql` driver sends a parameterless `ExecContext` call as `COM_QUERY`
(text protocol), which StarRocks supports for all statement types.

This plugin is otherwise identical in behaviour to the upstream MySQL plugin: it
uses `connutil.SQLConnectionProducer` for connection management and generates
usernames from the same template format.

> **Note:** There is also a Vault bug where `defer stmt.Close()` is registered
> before the `nil` check on the result of `PrepareContext`, causing a nil pointer
> dereference panic instead of a clean error when StarRocks rejects the prepare.
> This plugin avoids the entire `COM_STMT_PREPARE` path, so the panic does not
> occur.

## Configuration

Configure a connection exactly as you would the MySQL plugin, but specify
`plugin_name = "starrocks-database-plugin"`:

```bash
vault write database/config/starrocks \
  plugin_name=starrocks-database-plugin \
  connection_url="{{username}}:{{password}}@tcp(your-starrocks-fe:9030)/" \
  username="vault_admin" \
  password="..." \
  allowed_roles="readonly,app"
```

### Creation statements

StarRocks uses a slightly different SQL dialect from MySQL. Example creation
statements for a read-only analytics role:

```sql
CREATE USER IF NOT EXISTS '{{name}}'@'%' IDENTIFIED BY '{{password}}';
GRANT SELECT ON ALL TABLES IN ALL DATABASES TO USER '{{name}}'@'%';
```

### Revocation statements

```sql
DROP USER IF EXISTS '{{name}}'@'%';
```

### Password rotation

Default rotation statement (used when none is configured):

```sql
ALTER USER '{{username}}'@'%' IDENTIFIED BY '{{password}}';
```

## Building

```bash
GOOS=linux GOARCH=amd64 go build \
  -o vault-plugin-database-starrocks \
  ./cmd/vault-plugin-database-starrocks
sha256sum vault-plugin-database-starrocks
```

## Installation

See the [Vault plugin documentation][vault-plugin-docs] for the general process.
The AMI build for the MIT OL Vault cluster downloads this binary automatically
from GitHub Releases and places it in `/var/lib/vault/plugins/`.

Register the plugin in Vault's catalog:

```bash
vault plugin register \
  -sha256="<sha256 from release>" \
  -command="vault-plugin-database-starrocks" \
  database \
  starrocks-database-plugin
```

## License

[BSD-3-Clause](LICENSE)

[vault-db]: https://developer.hashicorp.com/vault/docs/secrets/databases
[starrocks]: https://www.starrocks.io/
[vault-plugin-docs]: https://developer.hashicorp.com/vault/docs/plugins/plugin-architecture
