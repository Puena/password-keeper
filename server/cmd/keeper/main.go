package main

import (
	"log"

	"github.com/Puena/password-keeper/server/config"
	"github.com/Puena/password-keeper/server/internal/app"
)

func main() {
	config, err := config.Parse()
	if err != nil {
		log.Fatal("failed while trying parse config", err)
	}

	app, err := app.Init(config)
	if err != nil {
		log.Fatal("failed while trying init application", err)
	}

	err = app.Run()
	if err != nil {
		log.Fatal("unexpected app termination", err)
	}
}
