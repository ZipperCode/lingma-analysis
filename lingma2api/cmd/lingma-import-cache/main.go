package main

import (
	"flag"
	"log"
	"os"
	"path/filepath"
	"time"

	"lingma2api/internal/auth"
)

func main() {
	home, _ := os.UserHomeDir()
	defaultLingmaDir := filepath.Join(home, ".lingma")

	var (
		lingmaDir string
		output    string
	)

	flag.StringVar(&lingmaDir, "lingma-dir", defaultLingmaDir, "Lingma home directory used only for one-time credential migration")
	flag.StringVar(&output, "output", "./auth/credentials.json", "destination project credential file")
	flag.Parse()

	credentialFile, err := auth.ImportCredentialFileFromLingmaDir(lingmaDir, time.Now())
	if err != nil {
		log.Fatalf("import cache credential: %v", err)
	}
	if err := auth.SaveCredentialFile(output, credentialFile); err != nil {
		log.Fatalf("save credential file: %v", err)
	}

	log.Printf("project credential file written to %s", output)
}
