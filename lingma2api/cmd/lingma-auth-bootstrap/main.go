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
	"path/filepath"
	"strings"
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
		importLingmaCache bool
	)
	flag.StringVar(&clientID, "client-id", "", "OAuth client_id (optional for refresh when Lingma is running; required for new bootstrap)")
	flag.StringVar(&listenAddr, "listen-addr", "127.0.0.1:37510", "local callback listen address")
	flag.StringVar(&redirectURL, "redirect-url", "", "explicit redirect URL (defaults to http://<listen-addr>/callback)")
	flag.StringVar(&outputPath, "output", "./auth/credentials.json", "output credentials.json file")
	flag.BoolVar(&printOnly, "print-only", false, "only print authorize URL and PKCE values")
	flag.StringVar(&lingmaBin, "lingma-bin", "", "path to Lingma binary (auto-detect if empty)")
	flag.BoolVar(&useLingma, "use-lingma", true, "use local Lingma binary to complete credential derivation")
	flag.StringVar(&sessionKey, "session-key", "", "old Signature session_key for pure remote mode")
	flag.BoolVar(&captureClientID, "capture-client-id", false, "print browser-friendly Lingma login URL for capturing real client_id, then exit")
	flag.StringVar(&machineIDOverride, "machine-id", "", "machine_id used for capture mode (auto-generated UUID if empty)")
	flag.BoolVar(&importLingmaCache, "import-lingma-cache", false, "import credentials from ~/.lingma cache and exit")
	flag.StringVar(&machineIDOverride, "machine-id", "", "machine_id used for capture mode (auto-generated UUID if empty)")

	var (
		userInfoJSON    string
		userInfoFile    string
		loginURLOverride string
	)
	flag.StringVar(&userInfoJSON, "user-info-json", "", "window.user_info JSON from Lingma callback page (bypasses OAuth, no client_id needed)")
	flag.StringVar(&userInfoFile, "user-info-file", "", "file containing window.user_info JSON (bypasses OAuth, no client_id needed)")
	flag.StringVar(&loginURLOverride, "login-url", "", "window.login_url from Lingma callback page (for machine_id extraction)")

	var refreshFile string
	flag.StringVar(&refreshFile, "refresh", "", "refresh existing credentials.json (mutually exclusive with bootstrap flow)")

	flag.Parse()

	if importLingmaCache {
		stored, err := auth.TryImportFromLingmaCache(outputPath)
		if err != nil {
			log.Fatalf("import from ~/.lingma cache: %v", err)
		}
		fmt.Printf("Imported credentials from ~/.lingma cache.\n")
		fmt.Printf("  Source: %s\n", stored.Source)
		fmt.Printf("  UserID: %s\n", stored.Auth.UserID)
		fmt.Printf("  MachineID: %s\n", stored.Auth.MachineID)
		fmt.Printf("  TokenExpireTime: %s\n", stored.TokenExpireTime)
		fmt.Printf("  Saved to: %s\n", outputPath)
		fmt.Println("\nTip: If you have client_id, run with --refresh to refresh tokens via OAuth.")
		return
	}

	// Handle --user-info-json / --user-info-file: bypass OAuth entirely by using tokens
	// extracted directly from Lingma's callback page (window.user_info).
	userInfoRaw := userInfoJSON
	if userInfoRaw == "" && userInfoFile != "" {
		data, err := os.ReadFile(userInfoFile)
		if err != nil {
			log.Fatalf("read user-info-file: %v", err)
		}
		userInfoRaw = string(data)
	}
	if userInfoRaw != "" {
		runBootstrapFromUserInfo(userInfoRaw, loginURLOverride, sessionKey, outputPath)
		return
	}

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
		// No client_id: use Lingma login URL flow, which can produce
		// either auth/token params (Lingma-specific) or code (standard OAuth).
		// Also accept POST /submit-userinfo from bookmarklet.
		runBootstrapWithoutClientID(listenAddr, outputPath, sessionKey, useLingma, lingmaBin, machineIDOverride)
		return
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
	if clientID == "" {
		clientID = os.Getenv("LINGMA_CLIENT_ID")
	}

	var refresher auth.TokenRefresher
	if clientID != "" {
		refresher = auth.NewMultiRefresher(
			&auth.OAuthRefresher{ClientID: clientID},
			&auth.WSRefresher{},
		)
		fmt.Println("Using OAuth refresh (with WebSocket fallback)...")
	} else {
		refresher = &auth.WSRefresher{}
		fmt.Println("No --client-id provided, using Lingma WebSocket for token refresh...")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	if err := auth.RefreshAndSave(ctx, refreshFile, refresher, useLingma, lingmaBin); err != nil {
		log.Fatalf("refresh failed: %v", err)
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

// runBootstrapWithoutClientID handles bootstrap when client_id is unavailable.
// It generates a Lingma login URL, waits for the callback, and tries multiple formats:
//   - POST /submit-userinfo (body JSON with userInfo + loginUrl)
//   - GET ?auth=...&token=... (Lingma-specific callback, Encode=1 encoded)
//   - GET ?code=... (standard OAuth — requires client_id, extracted from Referer if possible)
func runBootstrapWithoutClientID(listenAddr, outputPath, sessionKey string, useLingma bool, lingmaBin, machineIDOverride string) {
	machineID := machineIDOverride
	if machineID == "" {
		machineID = auth.NewMachineID()
		fmt.Printf("Auto-generated machine_id: %s\n", machineID)
	}

	// Generate Lingma login URL
	loginURL, state, verifier, err := auth.BuildLingmaLoginEntryURL(auth.LingmaLoginEntryConfig{
		MachineID: machineID,
		Port:      portFromListenAddr(listenAddr),
	})
	if err != nil {
		log.Fatalf("build lingma login entry url: %v", err)
	}

	browserURL, err := auth.WrapLingmaLoginURLForBrowser(loginURL)
	if err != nil {
		log.Fatalf("wrap login url: %v", err)
	}

	fmt.Println("=== No client_id provided — using Lingma login URL flow ===")
	fmt.Println()
	fmt.Println("1. Open the following URL in your browser:")
	fmt.Println()
	fmt.Println(browserURL)
	fmt.Println()
	fmt.Println("2. Complete Alibaba Cloud login.")
	fmt.Println("3. After login, you'll be redirected to a local page.")
	fmt.Println("4. On that page, press F12 → Console → paste and run:")
	fmt.Println()
	fmt.Println(`   fetch('http://` + listenAddr + `/submit-userinfo', {`)
	fmt.Println(`     method: 'POST',`)
	fmt.Println(`     headers: {'Content-Type': 'application/json'},`)
	fmt.Println(`     body: JSON.stringify({userInfo: window.user_info, loginUrl: window.login_url})`)
	fmt.Println(`   }).then(r => r.text()).then(console.log)`)
	fmt.Println()
	fmt.Println("Alternatively, wait for the standard OAuth redirect.")
	fmt.Printf("Callback server listening on %s (timeout 5 min)...\n", listenAddr)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	capture, err := auth.WaitForCallback(ctx, listenAddr, "/callback")
	if err != nil {
		log.Fatalf("wait for callback: %v", err)
	}

	_ = state
	_ = verifier

	// 1. Handle POST /submit-userinfo (bookmarklet body)
	if len(capture.Body) > 0 {
		handleSubmitUserInfo(capture.Body, outputPath, sessionKey)
		return
	}

	// 2. Handle Lingma-specific ?auth=...&token=... callback
	authParam := capture.Query.Get("auth")
	tokenParam := capture.Query.Get("token")
	if authParam != "" || tokenParam != "" {
		handleAuthTokenCallback(authParam, tokenParam, capture.Referer, machineID, outputPath, sessionKey)
		return
	}

	// 3. Handle standard OAuth ?code=... callback
	code := capture.Query.Get("code")
	if code != "" {
		// Try to get client_id from Referer
		extractedClientID := tryExtractClientIDFromReferer(capture.Referer)
		if extractedClientID != "" {
			fmt.Printf("Extracted client_id from Referer: %s\n", extractedClientID)
			handleStandardCodeCallback(ctx, code, listenAddr, extractedClientID, "", machineID, outputPath, sessionKey, useLingma, lingmaBin)
			return
		}
		log.Fatal("callback contained authorization code but no client_id available.\n" +
			"Run with --client-id <YOUR_CLIENT_ID> to complete.\n" +
			"Or use the bookmarklet method (step 4 above) to submit window.user_info directly.")
	}

	log.Fatalf("callback did not contain recognizable authentication data (path=%s, query=%v)", capture.Path, capture.Query)
}

// runBootstrapFromUserInfo implements the --user-info-json / --user-info-file flow.
func runBootstrapFromUserInfo(userInfoJSON, loginURL, sessionKey, outputPath string) {
	fmt.Println("=== Extracting tokens from window.user_info JSON ===")
	extracted, err := auth.ExtractFromCallbackPage(userInfoJSON, loginURL)
	if err != nil {
		log.Fatalf("parse user_info: %v", err)
	}
	fmt.Printf("  AccessToken:  %s\n", maskValue(extracted.AccessToken, 15))
	fmt.Printf("  RefreshToken: %s\n", maskValue(extracted.RefreshToken, 15))
	fmt.Printf("  UserID:       %s\n", extracted.UserID)
	fmt.Printf("  MachineID:    %s\n", extracted.MachineID)
	fmt.Printf("  ExpireTime:   %s\n", extracted.TokenExpireMs)

	deriveAndSave(extracted.AccessToken, extracted.RefreshToken, extracted.UserID, extracted.Username,
		extracted.MachineID, extracted.TokenExpireMs, sessionKey, false, "", outputPath)
}

// handleSubmitUserInfo processes the POST /submit-userinfo bookmarklet body.
func handleSubmitUserInfo(body []byte, outputPath, sessionKey string) {
	fmt.Println("=== Processing bookmarklet submission ===")

	var submission struct {
		UserInfo string `json:"userInfo"`
		LoginURL string `json:"loginUrl"`
	}
	if err := json.Unmarshal(body, &submission); err != nil {
		log.Fatalf("parse submit-userinfo body: %v\nRaw: %s", err, string(body))
	}
	if submission.UserInfo == "" {
		log.Fatal("submit-userinfo body missing userInfo field")
	}

	extracted, err := auth.ExtractFromCallbackPage(submission.UserInfo, submission.LoginURL)
	if err != nil {
		log.Fatalf("extract from callback page: %v", err)
	}
	fmt.Printf("  AccessToken:  %s\n", maskValue(extracted.AccessToken, 15))
	fmt.Printf("  UserID:       %s\n", extracted.UserID)
	fmt.Printf("  MachineID:    %s\n", extracted.MachineID)

	deriveAndSave(extracted.AccessToken, extracted.RefreshToken, extracted.UserID, extracted.Username,
		extracted.MachineID, extracted.TokenExpireMs, sessionKey, false, "", outputPath)
}

// handleAuthTokenCallback processes Lingma-specific ?auth=...&token=... callbacks.
func handleAuthTokenCallback(authEncoded, tokenEncoded, referer, machineID, outputPath, sessionKey string) {
	fmt.Println("=== Lingma-specific callback detected (auth/token params) ===")
	fmt.Printf("  auth:  %s...\n", maskValue(authEncoded, 20))
	fmt.Printf("  token: %s...\n", maskValue(tokenEncoded, 20))

	// Try to decode auth and token with Encode=1
	authRaw := auth.LingmaDecode(authEncoded)
	tokenRaw := auth.LingmaDecode(tokenEncoded)
	if authRaw == nil || tokenRaw == nil {
		log.Fatal("could not Encode=1 decode auth/token params")
	}
	fmt.Printf("  Auth decoded:  %d bytes\n", len(authRaw))
	fmt.Printf("  Token decoded: %d bytes\n", len(tokenRaw))

	// Try to extract readable parts from the decoded data
	authStr := string(authRaw)
	tokenStr := string(tokenRaw)
	fmt.Printf("  Auth (text):  %s\n", maskValue(authStr, 80))
	fmt.Printf("  Token (text): %s\n", maskValue(tokenStr, 80))

	// Save raw decoded data for now; the format is Lingma-specific binary
	output := map[string]interface{}{
		"schema_version": 1,
		"source":         "lingma_auth_token_callback",
		"machine_id":     machineID,
		"auth_decoded":   authStr,
		"token_decoded":  tokenStr,
	}
	os.MkdirAll(filepathBase(outputPath), 0o755)
	data, _ := json.MarshalIndent(output, "", "  ")
	os.WriteFile(outputPath+"-raw.json", data, 0o600)
	fmt.Printf("\nRaw decoded data saved to %s-raw.json\n", outputPath)
	fmt.Println("Full decoding of auth/token format is under investigation.")
	fmt.Println("For now, use --user-info-json with window.user_info from the browser console.")
	os.Exit(1)
}

// tryExtractClientIDFromReferer attempts to extract client_id from the Referer header.
func tryExtractClientIDFromReferer(referer string) string {
	if referer == "" {
		return ""
	}
	// Look for client_id= in the referer URL
	idx := strings.Index(referer, "client_id=")
	if idx < 0 {
		return ""
	}
	value := referer[idx+len("client_id="):]
	if end := strings.IndexAny(value, "& "); end >= 0 {
		value = value[:end]
	}
	return value
}

// handleStandardCodeCallback processes a standard OAuth authorization code callback.
func handleStandardCodeCallback(ctx context.Context, code, listenAddr, clientID, codeVerifier, machineID, outputPath, sessionKey string, useLingma bool, lingmaBin string) {
	redirectURL, err := auth.CallbackURLFromListenAddr(listenAddr)
	if err != nil {
		log.Fatalf("build redirect url: %v", err)
	}

	fmt.Printf("Captured authorization code; exchanging with client_id=%s...\n", clientID)
	tokens, err := auth.ExchangeCodeForTokens(ctx, auth.TokenExchangeConfig{
		Code:         code,
		RedirectURL:  redirectURL,
		ClientID:     clientID,
		CodeVerifier: codeVerifier,
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

	expireMs := ""
	if tokens.ExpiresIn > 0 {
		expireMs = fmt.Sprintf("%d", time.Now().UnixMilli()+int64(tokens.ExpiresIn)*1000)
	}

	deriveAndSave(tokens.AccessToken, tokens.RefreshToken, userID, username, machineID, expireMs, sessionKey, useLingma, lingmaBin, outputPath)
}

// deriveAndSave is the unified credential derivation + save step used by all bootstrap paths.
func deriveAndSave(accessToken, refreshToken, userID, username, machineID, tokenExpireMs, sessionKey string, useLingma bool, lingmaBin, outputPath string) {
	fmt.Println("\n=== Deriving credentials ===")

	if machineID == "" {
		machineID = auth.NewMachineID()
		fmt.Printf("Auto-generated machine_id: %s\n", machineID)
	}

	var stored proxy.StoredCredentialFile
	var err error

	if useLingma {
		fmt.Println("Starting Lingma to sync credentials...")
		stored, err = auth.DeriveCredentialsWithLingma(auth.LingmaBridgeConfig{
			LingmaBinary:  lingmaBin,
			AccessToken:   accessToken,
			RefreshToken:  refreshToken,
			UserID:        userID,
			Username:      username,
			TokenExpireMs: tokenExpireMs,
		})
	} else {
		fmt.Println("Calling remote user/login...")
		stored, err = auth.DeriveCredentialsRemotely(auth.RemoteLoginConfig{
			AccessToken:   accessToken,
			RefreshToken:  refreshToken,
			UserID:        userID,
			Username:      username,
			MachineID:     machineID,
			TokenExpireMs: tokenExpireMs,
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
	if stored.Auth.CosyKey != "" {
		fmt.Println("cosy_key: PRESENT")
	} else {
		fmt.Println("cosy_key: MISSING — derivation may need Lingma binary or v3 endpoint fix")
	}
	fmt.Println("lingma2api is now ready to run with this credentials file.")
}

func portFromListenAddr(listenAddr string) string {
	_, port, err := net.SplitHostPort(listenAddr)
	if err != nil || port == "" {
		return "37510"
	}
	return port
}

func filepathBase(path string) string {
	dir := filepath.Dir(path)
	if dir == "." {
		return "."
	}
	return dir
}
