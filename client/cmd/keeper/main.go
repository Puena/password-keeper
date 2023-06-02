package main

import (
	"log"

	"github.com/Puena/password-keeper/client/config"
	"github.com/Puena/password-keeper/client/internal/app"
)

var (
	version  string // build version tag.
	build    string // build time tag.
	release  bool   // build release tag.
	host     string // build host tag.
	doc      string // build doc tag.
	certData string // build cert data tag.
)

func main() {
	cfg, err := config.New()
	if err != nil {
		log.Fatal(err)
	}

	if host == "" {
		host = "localhost:3030"
	}

	cfg.AddBuildInfo(&config.BuildInfo{
		Version:  version,
		Time:     build,
		Release:  release,
		Host:     host,
		CertFile: certData,
	})

	app, err := app.New(cfg)
	if err != nil {
		log.Fatal(err)
	}

	if doc != "" {
		err = app.GenMarkdownDoc(doc)
		if err != nil {
			log.Fatal(err)
		}
	}

	err = app.Run()
	if err != nil {
		log.Fatal(err)
	}
}
