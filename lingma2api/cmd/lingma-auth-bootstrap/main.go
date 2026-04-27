package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/url"
	"time"

	"lingma2api/internal/auth"
	"lingma2api/internal/proxy"
)

func main() {
	var (
		clientID    string
		listenAddr  string
		redirectURL string
		outputPath  string
		printOnly   bool
		lingmaBin   string
		useLingma   bool
		sessionKey  string
	)
	flag.StringVar(&clientID, "client-id", "", "OAuth client_id (defaults to auto-generated machine_id)")
	flag.StringVar(&listenAddr, "listen-addr", "127.0.0.1:37510", "local callback listen address")
	flag.StringVar(&redirectURL, "redirect-url", "", "explicit redirect URL (defaults to http://<listen-addr>/callback)")
	flag.StringVar(&outputPath, "output", "./auth/credentials.json", "output credentials.json file")
	flag.BoolVar(&printOnly, "print-only", false, "only print authorize URL and PKCE values")
	flag.StringVar(&lingmaBin, "lingma-bin", "", "path to Lingma binary (auto-detect if empty)")
	flag.BoolVar(&useLingma, "use-lingma", true, "use local Lingma binary to complete credential derivation")
	flag.StringVar(&sessionKey, "session-key", "", "old Signature session_key for pure remote mode")
	flag.Parse()

	if redirectURL == "" {
		var err error
		redirectURL, err = auth.CallbackURLFromListenAddr(listenAddr)
		if err != nil {
			log.Fatal(err)
		}
	}

	if clientID == "" {
		clientID = auth.NewMachineID()
		fmt.Printf("Auto-generated machine_id (used as client_id): %s\n", clientID)
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

	var stored proxy.StoredCredentialFile
	if useLingma {
		stored, err = deriveWithLingma(lingmaBin, tokens, clientID, userID, username)
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
			MachineID:     clientID,
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
		stored.Auth.MachineID = clientID
	}

	if err := auth.SaveCredentialFile(outputPath, stored); err != nil {
		log.Fatalf("save credentials: %v", err)
	}

	fmt.Printf("\nCredentials written to %s\n", outputPath)
	fmt.Println("lingma2api is now ready to run with this credentials file.")
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
