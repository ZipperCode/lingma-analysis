package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"lingma2api/internal/auth"
)

type callbackArtifact struct {
	AuthorizeURL string               `json:"authorize_url"`
	State        string               `json:"state"`
	CodeVerifier string               `json:"code_verifier"`
	Capture      auth.CallbackCapture `json:"capture"`
}

func main() {
	var (
		clientID             string
		listenAddr           string
		redirectURL          string
		outputPath           string
		printOnly            bool
		seedCallbackHTML     string
		useMachineIDAsClient bool
		loginURL             string
	)

	flag.StringVar(&clientID, "client-id", "", "OAuth client_id used to generate the authorize URL")
	flag.StringVar(&listenAddr, "listen-addr", "127.0.0.1:37510", "local callback listen address")
	flag.StringVar(&redirectURL, "redirect-url", "", "explicit redirect URL; defaults to http://<listen-addr>/callback")
	flag.StringVar(&outputPath, "output", "./auth/bootstrap-callback.json", "file to store callback capture artifact")
	flag.BoolVar(&printOnly, "print-only", false, "only print authorize URL and PKCE values")
	flag.StringVar(&seedCallbackHTML, "seed-callback-html", "", "optional callback.html path used to preload machine_id and prior callback hints")
	flag.BoolVar(&useMachineIDAsClient, "use-machine-id-as-client-id", false, "treat seeded machine_id as a one-time candidate client_id for validation")
	flag.StringVar(&loginURL, "login-url", "", "use a pre-generated Lingma login URL instead of constructing an OAuth authorize URL")
	flag.Parse()

	var hints auth.CallbackHTMLHints
	if seedCallbackHTML != "" {
		raw, err := os.ReadFile(seedCallbackHTML)
		if err != nil {
			log.Fatalf("read seed callback html: %v", err)
		}
		hints, err = auth.ParseCallbackHTMLHints(raw)
		if err != nil {
			log.Fatalf("parse seed callback html: %v", err)
		}
		if useMachineIDAsClient && clientID == "" {
			clientID = hints.MachineID
		}
	}

	if redirectURL == "" {
		var err error
		redirectURL, err = auth.CallbackURLFromListenAddr(listenAddr)
		if err != nil {
			log.Fatal(err)
		}
	}

	authorizeURL := loginURL
	state := ""
	verifier := ""
	if authorizeURL == "" {
		var err error
		authorizeURL, state, verifier, err = auth.BuildAuthorizeURL(auth.AuthorizeConfig{
			ClientID:    clientID,
			RedirectURL: redirectURL,
		})
		if err != nil {
			log.Fatalf("build authorize url: %v", err)
		}
	} else {
		var err error
		authorizeURL, err = auth.RewriteLingmaLoginURLPort(authorizeURL, listenAddr)
		if err != nil {
			log.Fatalf("rewrite login url port: %v", err)
		}
		authorizeURL, err = auth.WrapLingmaLoginURLForBrowser(authorizeURL)
		if err != nil {
			log.Fatalf("wrap login url: %v", err)
		}
		parsed, err := url.Parse(authorizeURL)
		if err != nil {
			log.Fatalf("parse login url: %v", err)
		}
		state = parsed.Query().Get("state")
	}

	fmt.Printf("Authorize URL:\n%s\n\n", authorizeURL)
	if state != "" {
		fmt.Printf("State: %s\n", state)
	}
	if verifier != "" {
		fmt.Printf("Code verifier: %s\n", verifier)
	}
	if hints.MachineID != "" {
		fmt.Printf("Seed machine_id: %s\n", hints.MachineID)
	}
	if hints.SecurityOAuthToken != "" {
		fmt.Printf("Seed securityOauthToken: %s\n", maskValue(hints.SecurityOAuthToken, 10))
	}
	if useMachineIDAsClient {
		fmt.Printf("Client ID candidate mode: machine_id -> client_id (%s)\n", clientID)
	}
	if loginURL != "" {
		fmt.Println("Mode: using pre-generated Lingma login URL")
	}

	if printOnly {
		return
	}

	fmt.Printf("\nOpen the URL in your browser, complete login, then wait for callback on %s.\n", redirectURL)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	capture, err := auth.WaitForCallback(ctx, listenAddr, "/callback")
	if err != nil {
		log.Fatalf("wait for callback: %v", err)
	}

	artifact := callbackArtifact{
		AuthorizeURL: authorizeURL,
		State:        state,
		CodeVerifier: verifier,
		Capture:      capture,
	}
	if err := saveArtifact(outputPath, artifact); err != nil {
		log.Fatalf("save callback artifact: %v", err)
	}

	fmt.Printf("\nCaptured callback and saved artifact to %s\n", outputPath)
	fmt.Println("This artifact does not yet produce runtime credentials by itself; complete token exchange is still required.")
}

func saveArtifact(path string, payload callbackArtifact) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return os.WriteFile(path, data, 0o600)
}

func maskValue(value string, keep int) string {
	if value == "" {
		return ""
	}
	if len(value) <= keep {
		return value
	}
	return value[:keep] + "..."
}
