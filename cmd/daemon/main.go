package main

import (
	"context"
	"crypto/tls"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/ageis/secrets-manager/internal/api"
	"github.com/ageis/secrets-manager/internal/auth"
	"github.com/ageis/secrets-manager/internal/db"
)

func main() {
	addr := flag.String("addr", ":8443", "listen address")
	dbPath := flag.String("db", "secrets.db", "SQLite database path")

	certFile := flag.String("tls-cert", "", "TLS certificate file (PEM)")
	keyFile := flag.String("tls-key", "", "TLS private key file (PEM)")
	caFile := flag.String("tls-ca", "", "CA certificate for mTLS client verification")
	requireMTLS := flag.Bool("mtls", false, "require client certificates")

	jwtSecretFile := flag.String("jwt-secret-file", "", "file containing JWT HMAC secret")
	corsOriginsStr := flag.String("cors-origins", "", "comma-separated allowed CORS origins")

	flag.Parse()

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))

	database, err := db.Open(*dbPath)
	if err != nil {
		logger.Error("failed to open database", "error", err)
		os.Exit(1)
	}

	if err := db.WaitForDB(database, 5*time.Second); err != nil {
		logger.Error("database not ready", "error", err)
		database.Close()
		os.Exit(1)
	}

	var tlsCfg *tls.Config
	if *certFile != "" && *keyFile != "" {
		tlsCfg, err = auth.LoadTLSConfig(*certFile, *keyFile, *caFile, *requireMTLS)
		if err != nil {
			logger.Error("TLS config failed", "error", err)
			database.Close()
			os.Exit(1)
		}
	}

	authCfg := &auth.Config{
		RequireMTLS: *requireMTLS,
	}
	if *jwtSecretFile != "" {
		secret, err := os.ReadFile(*jwtSecretFile)
		if err != nil {
			logger.Error("failed to read JWT secret", "error", err)
			database.Close()
			os.Exit(1)
		}
		authCfg.JWTSecret = secret
	}

	var corsOrigins []string
	if *corsOriginsStr != "" {
		for _, o := range strings.Split(*corsOriginsStr, ",") {
			o = strings.TrimSpace(o)
			if o != "" {
				corsOrigins = append(corsOrigins, o)
			}
		}
	}

	revoker := auth.NewTokenRevoker(24 * time.Hour)
	defer revoker.Stop()

	server := api.New(database, logger, revoker, corsOrigins)
	srv := server.CreateHTTPServer(*addr, tlsCfg, authCfg)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	go func() {
		var listenErr error
		if tlsCfg != nil {
			listenErr = srv.ListenAndServeTLS("", "")
		} else {
			listenErr = srv.ListenAndServe()
		}
		if listenErr != nil && listenErr.Error() != "http: Server closed" {
			logger.Error("server error", "error", listenErr)
		}
	}()

	logger.Info("daemon started", "addr", *addr, "db", *dbPath, "mtls", *requireMTLS)
	<-ctx.Done()
	logger.Info("shutting down...")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		logger.Error("HTTP shutdown error", "error", err)
	}
	logger.Info("HTTP server stopped")

	if err := database.Close(); err != nil {
		logger.Error("db close error", "error", err)
	}
	logger.Info("shutdown complete")
}
