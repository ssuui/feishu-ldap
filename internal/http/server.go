package http

import (
	"context"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"

	"feishu-ldap-server/config"
	"feishu-ldap-server/internal/common"
	"feishu-ldap-server/internal/contact"
	"feishu-ldap-server/internal/feishu"
	"feishu-ldap-server/internal/http/handlers"
	"feishu-ldap-server/internal/http/middleware"
	"feishu-ldap-server/internal/session"
)

type Server struct {
	server *http.Server
	router *gin.Engine
	cache  *contact.Cache
	cfg    *config.Config
	client *feishu.Client
	sess   *session.Manager
	wg     sync.WaitGroup
}

type Config struct {
	Cache  *contact.Cache
	Config *config.Config
}

func NewServer(cfg Config) *Server {
	gin.SetMode(gin.ReleaseMode)

	router := gin.New()
	router.Use(gin.Recovery())
	router.Use(corsMiddleware())

	return &Server{
		router: router,
		cache:  cfg.Cache,
		cfg:    cfg.Config,
	}
}

func (s *Server) SetClient(client *feishu.Client) {
	s.client = client
}

func (s *Server) SetSession(sess *session.Manager) {
	s.sess = sess
}

func (s *Server) SetupRoutes() {
	authHandler := handlers.NewAuthHandler(s.cfg, s.client, s.sess)
	totpHandler := handlers.NewTOTPHandler(s.cache)

	api := s.router.Group("/api")
	{
		api.GET("/health", s.handleHealth)

		auth := api.Group("/auth")
		{
			auth.GET("/login", authHandler.HandleLogin)
			auth.GET("/callback", authHandler.HandleCallback)
		}

		protected := api.Group("")
		protected.Use(middleware.AuthRequired())
		{
			totp := protected.Group("/totp")
			{
				totp.GET("/code", totpHandler.HandleGetCode)
			}

			user := protected.Group("/user")
			{
				user.GET("/info", totpHandler.HandleGetUserInfo)
			}
		}
	}
}

func (s *Server) Start(address string) error {
	s.SetupRoutes()

	s.server = &http.Server{
		Addr:         address,
		Handler:      s.router,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		log.Printf("[HTTP] Server starting on %s", address)
		if err := s.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("[HTTP] Server error: %v", err)
		}
	}()

	time.Sleep(100 * time.Millisecond)
	log.Printf("[HTTP] Server started successfully")
	return nil
}

func (s *Server) Stop() error {
	if s.server == nil {
		return nil
	}

	log.Println("[HTTP] Stopping server...")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := s.server.Shutdown(ctx); err != nil {
		return err
	}

	s.wg.Wait()
	log.Println("[HTTP] Server stopped")
	return nil
}

func corsMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("Access-Control-Allow-Origin", "*")
		c.Header("Access-Control-Allow-Methods", "*")
		c.Header("Access-Control-Allow-Headers", "*")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}

		c.Next()
	}
}

func (s *Server) handleHealth(c *gin.Context) {
	common.SuccessWithMessage(c, "OK", map[string]interface{}{
		"timestamp": time.Now().Format(time.RFC3339),
	})
}
