package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/url"
	"os"
	"time"

	"lingma2api/internal/auth"
	"lingma2api/internal/proxy"
)

func main() {
	var (
		clientID         string
		listenAddr       string
		redirectURL      string
		outputPath       string
		printOnly        bool
		lingmaBin        string
		useLingma        bool
		sessionKey       string
		captureClientID  bool
		machineIDOverride string
	)
	flag.StringVar(&clientID, "client-id", "", "OAuth client_id (REQUIRED unless --capture-client-id; obtain via Stage A documented in docs/topics/client-id-extraction.md)")
	flag.StringVar(&listenAddr, "listen-addr", "127.0.0.1:37510", "local callback listen address")
	flag.StringVar(&redirectURL, "redirect-url", "", "explicit redirect URL (defaults to http://<listen-addr>/callback)")
	flag.StringVar(&outputPath, "output", "./auth/credentials.json", "output credentials.json file")
	flag.BoolVar(&printOnly, "print-only", false, "only print authorize URL and PKCE values")
	flag.StringVar(&lingmaBin, "lingma-bin", "", "path to Lingma binary (auto-detect if empty)")
	flag.BoolVar(&useLingma, "use-lingma", true, "use local Lingma binary to complete credential derivation")
	flag.StringVar(&sessionKey, "session-key", "", "old Signature session_key for pure remote mode")
	flag.BoolVar(&captureClientID, "capture-client-id", false, "print browser-friendly Lingma login URL for capturing real client_id, then exit")
	flag.StringVar(&machineIDOverride, "machine-id", "", "machine_id used for capture mode (auto-generated UUID if empty)")

	var refreshFile string
	flag.StringVar(&refreshFile, "refresh", "", "refresh existing credentials.json (mutually exclusive with bootstrap flow)")

	flag.Parse()

	if captureClientID {
		runCaptureClientID(listenAddr, machineIDOverride)
		return
	}

	if refreshFile != "" {
		runRefresh(refreshFile, clientID, sessionKey, useLingma, lingmaBin)
		return
	}

	if redirectURL == "" {
		var err error
		redirectURL, err = auth.CallbackURLFromListenAddr(listenAddr)
		if err != nil {
			log.Fatal(err)
		}
	}

	if clientID == "" {
		log.Fatal("missing --client-id. Run with --capture-client-id first to obtain the OAuth client_id from the browser; see docs/topics/client-id-extraction.md.")
	}

	authorizeURL, state, verifier, err := auth.BuildAuthorizeURL(auth.AuthorizeConfig{
		ClientID:    clientID,
		RedirectURL: redirectURL,
	})
	if err != nil {
		log.Fatalf("build authorize url: %v", err)
	}

	fmt.Printf("Authorize URL:\n%s\n\n", authorizeURL)
	fmt.Printf("State: %s\n", state)
	fmt.Printf("Code verifier: %s\n\n", verifier)

	if printOnly {
		return
	}

	fmt.Printf("Open the URL in your browser, complete login, then wait for callback on %s.\n", redirectURL)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	capture, err := auth.WaitForCallback(ctx, listenAddr, "/callback")
	if err != nil {
		log.Fatalf("wait for callback: %v", err)
	}

	code := capture.Query.Get("code")
	if code == "" {
		log.Fatal("callback did not contain authorization code")
	}
	fmt.Printf("Captured authorization code.\n")

	tokens, err := auth.ExchangeCodeForTokens(ctx, auth.TokenExchangeConfig{
		Code:         code,
		RedirectURL:  redirectURL,
		ClientID:     clientID,
		CodeVerifier: verifier,
	})
	if err != nil {
		log.Fatalf("token exchange: %v", err)
	}
	fmt.Printf("Token exchange successful (access_token: %s...).\n", maskValue(tokens.AccessToken, 15))

	userID := ""
	username := ""
	if tokens.IDToken != "" {
		claims, err := auth.DecodeIDTokenClaims(tokens.IDToken)
		if err != nil {
			fmt.Printf("Warning: could not decode id_token: %v\n", err)
		} else {
			userID = claims.Sub
			username = claims.Name
			if username == "" {
				username = claims.Email
			}
			fmt.Printf("ID token: sub=%s name=%s\n", userID, username)
		}
	}

	machineID := machineIDOverride
	if machineID == "" {
		machineID = auth.NewMachineID()
		fmt.Printf("Auto-generated machine_id: %s\n", machineID)
	}

	var stored proxy.StoredCredentialFile
	if useLingma {
		stored, err = deriveWithLingma(lingmaBin, tokens, machineID, userID, username)
	} else {
		expireMs := ""
		if tokens.ExpiresIn > 0 {
			expireMs = fmt.Sprintf("%d", time.Now().UnixMilli()+int64(tokens.ExpiresIn)*1000)
		}
		stored, err = auth.DeriveCredentialsRemotely(auth.RemoteLoginConfig{
			AccessToken:   tokens.AccessToken,
			RefreshToken:  tokens.RefreshToken,
			UserID:        userID,
			Username:      username,
			MachineID:     machineID,
			TokenExpireMs: expireMs,
			SessionKey:    sessionKey,
		})
	}
	if err != nil {
		log.Fatalf("derive credentials: %v", err)
	}

	if userID != "" && stored.Auth.UserID == "" {
		stored.Auth.UserID = userID
	}
	if stored.Auth.MachineID == "" {
		stored.Auth.MachineID = machineID
	}

	if err := auth.SaveCredentialFile(outputPath, stored); err != nil {
		log.Fatalf("save credentials: %v", err)
	}

	fmt.Printf("\nCredentials written to %s\n", outputPath)
	fmt.Println("lingma2api is now ready to run with this credentials file.")
}

// runCaptureClientID prints a browser-friendly Lingma login URL whose 302 chain
// will pass through signin.alibabacloud.com/oauth2/v1/auth?client_id=<REAL>.
// The user is expected to copy/paste the URL into a browser, complete the
// Alibaba Cloud login, and capture client_id from DevTools Network panel.
func runCaptureClientID(listenAddr, machineIDOverride string) {
	_, port, err := net.SplitHostPort(listenAddr)
	if err != nil || port == "" {
		log.Fatalf("invalid --listen-addr %q: %v", listenAddr, err)
	}

	loginURL, _, _, err := auth.BuildLingmaLoginEntryURL(auth.LingmaLoginEntryConfig{
		MachineID: machineIDOverride,
		Port:      port,
	})
	if err != nil {
		log.Fatalf("build lingma login entry url: %v", err)
	}

	browserURL, err := auth.WrapLingmaLoginURLForBrowser(loginURL)
	if err != nil {
		log.Fatalf("wrap login url: %v", err)
	}

	fmt.Println("=== Stage A: client_id capture mode ===")
	fmt.Println()
	fmt.Println("1. Open the following URL in your browser:")
	fmt.Println()
	fmt.Println(browserURL)
	fmt.Println()
	fmt.Println("2. Complete Alibaba Cloud login.")
	fmt.Println("3. Open DevTools (F12) -> Network panel BEFORE final redirect happens.")
	fmt.Println("   (If you missed it, refresh / re-open the URL above.)")
	fmt.Println("4. Locate request URL containing:")
	fmt.Println("       https://signin.alibabacloud.com/oauth2/v1/auth?client_id=<REAL_ID>&...")
	fmt.Println("5. Copy the client_id query parameter value.")
	fmt.Println("6. Save it to lingma2api/configs/client_id.txt (gitignored) for reuse, then re-run this CLI with:")
	fmt.Println("       lingma-auth-bootstrap --client-id <REAL_ID> --use-lingma=false")
	fmt.Println()
	fmt.Println("Underlying lingma login URL (in case wrap failed):")
	fmt.Println(loginURL)
}

func runRefresh(refreshFile, clientID, sessionKey string, useLingma bool, lingmaBin string) {
	data, err := os.ReadFile(refreshFile)
	if err != nil {
		log.Fatalf("read credentials file: %v", err)
	}
	var stored proxy.StoredCredentialFile
	if err := json.Unmarshal(data, &stored); err != nil {
		log.Fatalf("parse credentials file: %v", err)
	}

	if clientID == "" {
		clientID = os.Getenv("LINGMA_CLIENT_ID")
	}
	if clientID == "" {
		log.Fatal("missing --client-id or LINGMA_CLIENT_ID for refresh")
	}

	refreshToken := stored.OAuth.RefreshToken
	if refreshToken == "" {
		log.Fatal("credentials file missing refresh_token")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	tokens, err := auth.RefreshTokens(ctx, auth.RefreshTokenConfig{
		RefreshToken: refreshToken,
		ClientID:     clientID,
	})
	if err != nil {
		log.Fatalf("refresh tokens: %v", err)
	}
	fmt.Printf("Token refresh successful (access_token: %s...).\n", maskValue(tokens.AccessToken, 15))

	stored.OAuth.AccessToken = tokens.AccessToken
	stored.OAuth.RefreshToken = tokens.RefreshToken

	machineID := stored.Auth.MachineID
	if machineID == "" {
		machineID = auth.NewMachineID()
		fmt.Printf("Auto-generated machine_id: %s\n", machineID)
	}

	userID := stored.Auth.UserID
	username := ""

	var newStored proxy.StoredCredentialFile
	if useLingma {
		newStored, err = deriveWithLingma(lingmaBin, tokens, machineID, userID, username)
	} else {
		expireMs := ""
		if tokens.ExpiresIn > 0 {
			expireMs = fmt.Sprintf("%d", time.Now().UnixMilli()+int64(tokens.ExpiresIn)*1000)
		}
		newStored, err = auth.DeriveCredentialsRemotely(auth.RemoteLoginConfig{
			AccessToken:   tokens.AccessToken,
			RefreshToken:  tokens.RefreshToken,
			UserID:        userID,
			Username:      username,
			MachineID:     machineID,
			TokenExpireMs: expireMs,
			SessionKey:    sessionKey,
		})
	}
	if err != nil {
		log.Fatalf("derive credentials after refresh: %v", err)
	}

	if newStored.Source == "" {
		newStored.Source = stored.Source
	}
	if userID != "" && newStored.Auth.UserID == "" {
		newStored.Auth.UserID = userID
	}
	if newStored.Auth.MachineID == "" {
		newStored.Auth.MachineID = machineID
	}

	if err := auth.SaveCredentialFile(refreshFile, newStored); err != nil {
		log.Fatalf("save credentials: %v", err)
	}

	fmt.Printf("\nCredentials refreshed and written to %s\n", refreshFile)
}

func deriveWithLingma(lingmaBin string, tokens auth.ExchangedTokens, machineID, userID, username string) (proxy.StoredCredentialFile, error) {
	if lingmaBin == "" {
		var err error
		lingmaBin, err = auth.DefaultLingmaBinary()
		if err != nil {
			return proxy.StoredCredentialFile{}, fmt.Errorf("auto-detect Lingma binary failed; specify --lingma-bin or set --use-lingma=false: %w", err)
		}
		fmt.Printf("Detected Lingma binary: %s\n", lingmaBin)
	}

	expireMs := ""
	if tokens.ExpiresIn > 0 {
		expireMs = fmt.Sprintf("%d", time.Now().UnixMilli()+int64(tokens.ExpiresIn)*1000)
	}

	if userID == "" {
		parsed, err := url.Parse(tokens.AccessToken)
		if err == nil && parsed.Query().Get("sub") != "" {
			userID = parsed.Query().Get("sub")
		}
	}

	fmt.Println("Starting Lingma to sync credentials...")
	return auth.DeriveCredentialsWithLingma(auth.LingmaBridgeConfig{
		LingmaBinary:  lingmaBin,
		AccessToken:   tokens.AccessToken,
		RefreshToken:  tokens.RefreshToken,
		UserID:        userID,
		Username:      username,
		TokenExpireMs: expireMs,
	})
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
