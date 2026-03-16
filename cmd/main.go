package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"feishu-ldap-server/config"
	"feishu-ldap-server/internal/contact"
	"feishu-ldap-server/internal/feishu"
	http_util "feishu-ldap-server/internal/http"
	"feishu-ldap-server/internal/ldap"
	"feishu-ldap-server/internal/session"
)

func main() {
	log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)

	log.Println("========================================")
	log.Println("   FeiShu LDAP Service Starting...")
	log.Println("========================================")

	log.Println("[Main] Step 1: Loading configuration...")
	cfg, err := config.LoadConfig("config/config.yaml")
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}
	log.Printf("[Main] Configuration loaded: LDAP=%s, BaseDN=%s", cfg.LDAP.Address, cfg.LDAP.BaseDN)

	log.Println("[Main] Step 2: Initializing contact cache...")
	cache, err := contact.InitCache("runtime/contacts.json")
	if err != nil {
		log.Fatalf("Failed to init cache: %v", err)
	}

	cache.StartReloadListener()

	stats := cache.GetStats()
	log.Printf("[Main] Cache loaded: %d departments, %d users",
		stats["total_departments"], stats["total_users"])
	if stats["sync_time"] != "" {
		log.Printf("[Main] Last sync time: %s", stats["sync_time"])
	}

	var ldapServer *ldap.Server
	if cfg.LDAP.Enabled {
		log.Println("[Main] Step 3: Building LDAP server config...")
		ldapConfig := ldap.Config{
			Address:             cfg.LDAP.Address,
			BaseDN:              cfg.LDAP.BaseDN,
			ServiceBindDN:       cfg.LDAP.ServiceBindDN,
			ServiceBindPassword: cfg.LDAP.ServiceBindPassword,
			Cache:               cache,
		}

		log.Println("[Main] Step 4: Creating LDAP server...")
		ldapServer, err = ldap.NewServer(ldapConfig)
		if err != nil {
			log.Fatalf("Failed to create LDAP server: %v", err)
		}

		log.Println("[Main] Step 5: Starting LDAP server...")
		if err := ldapServer.Start(); err != nil {
			log.Fatalf("Failed to start LDAP server: %v", err)
		}
	}

	var httpServer *http_util.Server
	if cfg.Server.HTTPPort > 0 {
		log.Println("[Main] Step 6: Initializing session manager...")
		sessMgr, err := session.InitManager("runtime/sessions.json")
		if err != nil {
			log.Fatalf("Failed to init session manager: %v", err)
		}
		log.Printf("[Main] Session manager initialized: %d active sessions", sessMgr.GetSessionCount())

		log.Println("[Main] Step 7: Creating Feishu client...")
		feishuClient := feishu.NewClient(cfg.Feishu.AppID, cfg.Feishu.AppSecret)

		log.Println("[Main] Step 8: Creating HTTP server...")
		httpServer = http_util.NewServer(http_util.Config{
			Cache:  cache,
			Config: cfg,
		})
		httpServer.SetClient(feishuClient)
		httpServer.SetSession(sessMgr)

		httpAddr := fmt.Sprintf("0.0.0.0:%d", cfg.Server.HTTPPort)
		if err := httpServer.Start(httpAddr); err != nil {
			log.Fatalf("Failed to start HTTP server: %v", err)
		}
	}

	log.Println("========================================")
	log.Println("   Services are running!")
	log.Println("========================================")
	if cfg.LDAP.Enabled {
		log.Printf("   LDAP:       %s", cfg.LDAP.Address)
		log.Printf("   Base DN:    %s", cfg.LDAP.BaseDN)
		log.Printf("   Bind DN:    %s", cfg.LDAP.ServiceBindDN)
	}
	if cfg.Server.HTTPPort > 0 {
		log.Printf("   HTTP:       0.0.0.0:%d", cfg.Server.HTTPPort)
		log.Printf("   Health:     http://localhost:%d/api/health", cfg.Server.HTTPPort)
		log.Printf("   Login:      http://localhost:%d/api/auth/login?redirect_uri=http://localhost:8080", cfg.Server.HTTPPort)
		log.Printf("   Callback:   %s", cfg.Server.CallbackURL)
	}
	log.Println("========================================")
	log.Println("   Press Ctrl+C to stop")
	log.Println("========================================")

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	<-sigChan
	log.Println("Shutting down...")

	done := make(chan struct{})
	go func() {
		cache.Stop()
		if ldapServer != nil {
			if err := ldapServer.Stop(); err != nil {
				log.Printf("Error stopping LDAP server: %v", err)
			}
		}
		if httpServer != nil {
			if err := httpServer.Stop(); err != nil {
				log.Printf("Error stopping HTTP server: %v", err)
			}
		}
		close(done)
	}()

	select {
	case <-done:
		log.Println("Server stopped. Goodbye!")
	case <-time.After(5 * time.Second):
		log.Println("Shutdown timeout, forcing exit...")
		os.Exit(0)
	}
}
