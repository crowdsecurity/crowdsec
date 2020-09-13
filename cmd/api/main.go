package main

import (
	_ "github.com/mattn/go-sqlite3"
	log "github.com/sirupsen/logrus"
)

func main() {
	if err := rootCmd.Execute(); err != nil {
		log.Fatalf("While executing root command : %s", err)
	}
}
