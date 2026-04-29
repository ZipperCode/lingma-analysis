package main

import (
	"context"
	"embed"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"lingma2api/internal/api"
	"lingma2api/internal/auth"
	"lingma2api/internal/config"
	"lingma2api/internal/db"
	"lingma2api/internal/proxy"
)

//go:embed all:frontend-dist
var frontendDist embed.FS

func main() {
	var configPath string
	flag.StringVar(&configPath, "config", "./config.yaml", "path to config file")
	flag.Parse()

	cfg, err := config.Load(configPath)
	if err != nil {
		log.Fatalf("load config: %v", err)
	}

	signer := proxy.NewSignatureEngine(proxy.SignatureOptions{
		CosyVersion: cfg.Lingma.CosyVersion,
	})
	credentials := proxy.NewCredentialManager(cfg.Credential, time.Now)

	// Auto-import from ~/.lingma cache if auth file missing
	if _, err := os.Stat(cfg.Credential.AuthFile); os.IsNotExist(err) {
		if imported, err := auth.TryImportFromLingmaCache(cfg.Credential.AuthFile); err == nil {
			log.Printf("auto-imported credentials from ~/.lingma cache (source: %s)", imported.Source)
		}
	}

	// Setup auto-refresh: OAuth (if client_id available) -> WebSocket fallback
	var refresher auth.TokenRefresher
	if cfg.Lingma.ClientID != "" {
		refresher = auth.NewMultiRefresher(
			&auth.OAuthRefresher{ClientID: cfg.Lingma.ClientID},
			&auth.WSRefresher{},
		)
	} else {
		refresher = &auth.WSRefresher{}
	}
	credentials.SetRefreshFn(func(ctx context.Context) error {
		return auth.RefreshAndSave(ctx, cfg.Credential.AuthFile, refresher, true, "")
	})

	transport := proxy.NewCurlTransport(cfg.Lingma.BaseURL, signer, 90*time.Second)
	models := proxy.NewModelService(transport, credentials, proxy.DefaultAliases(), time.Now)
	sessions := proxy.NewSessionStore(time.Duration(cfg.Session.TTLMinutes)*time.Minute, cfg.Session.MaxSessions, time.Now)
	builder := proxy.NewBodyBuilder(cfg.Lingma.CosyVersion, time.Now, proxy.NewUUID, proxy.NewHexID)

	store, err := db.Open("./lingma2api.db")
	if err != nil {
		log.Fatalf("open db: %v", err)
	}
	if err := store.Migrate(); err != nil {
		log.Fatalf("migrate db: %v", err)
	}
	defer store.Close()

	// Start background log cleanup goroutine
	go func() {
		ticker := time.NewTicker(10 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				settings, _ := store.GetSettings(context.Background())
				retentionDays := 30
				if d, err := strconv.Atoi(settings["retention_days"]); err == nil {
					retentionDays = d
				}
				ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				affected, err := store.CleanupExpiredLogs(ctx, retentionDays)
				cancel()
				if err != nil {
					log.Printf("cleanup logs error: %v", err)
				} else if affected > 0 {
					log.Printf("cleaned up %d expired log(s)", affected)
				}
			}
		}
	}()

	bootstrapMgr := api.NewBootstrapManager(
		cfg.Credential.AuthFile,
		cfg.Lingma.ClientID,
		cfg.Lingma.OAuthListenAddr,
		cfg.Lingma.CosyVersion,
	)

	handler := api.NewServer(api.Dependencies{
		Credentials: credentials,
		Models:      models,
		Sessions:    sessions,
		Transport:   transport,
		Builder:     builder,
		AdminToken:  cfg.Server.AdminToken,
		Now:         time.Now,
		FrontendFS:  frontendDist,
		Bootstrap:   bootstrapMgr,
	}, store)

	server := &http.Server{
		Addr:              fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Server.Port),
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	go sweepSessions(ctx, sessions)
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
	}()

	log.Printf("lingma2api listening on %s", server.Addr)
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("listen: %v", err)
	}
}

func sweepSessions(ctx context.Context, store *proxy.SessionStore) {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			_ = store.SweepExpired(context.Background())
		}
	}
}
