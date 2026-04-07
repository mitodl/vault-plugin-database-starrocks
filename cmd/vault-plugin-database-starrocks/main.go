package main

import (
	"log"
	"os"

	"github.com/hashicorp/vault/api"
	dbplugin "github.com/hashicorp/vault/sdk/database/dbplugin/v5"
	"github.com/mitodl/vault-plugin-database-starrocks/starrocks"
)

func main() {
	// Parse TLS flags injected by Vault when starting the plugin process.
	apiClientMeta := &api.PluginAPIClientMeta{}
	flags := apiClientMeta.FlagSet()
	if err := flags.Parse(os.Args[1:]); err != nil {
		log.Println(err)
		os.Exit(1)
	}

	if err := run(); err != nil {
		log.Println(err)
		os.Exit(1)
	}
}

func run() error {
	dbplugin.ServeMultiplex(starrocks.New)
	return nil
}
