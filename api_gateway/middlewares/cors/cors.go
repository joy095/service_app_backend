package middleware

import (
	"os"
	"strings"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/joy095/api-gateway/config"
	"github.com/joy095/api-gateway/logger"
)

// CorsMiddleware sets up CORS settings
func CorsMiddleware() gin.HandlerFunc {
	config.LoadEnv()

	allowedOrigins := os.Getenv("ALLOWED_ORIGINS")
	if allowedOrigins == "" {
		logger.InfoLogger.Info("ALLOWED_ORIGINS not set, defaulting to allow all origins (*)")
		allowedOrigins = "*"
	}

	origins := strings.Split(allowedOrigins, ",")
	for i := range origins {
		origins[i] = strings.TrimSpace(origins[i])
	}

	corsConfig := cors.Config{
		AllowMethods:     []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Content-Length", "Accept-Encoding", "X-CSRF-Token", "Authorization", "Refresh_token", "Accept", "Cache-Control", "X-Requested-With"},
		ExposeHeaders:    []string{"Content-Length", "Content-Type", "Authorization", "New-Access-Token", "New-Refresh-Token"},
		MaxAge:           12 * time.Hour,
		AllowCredentials: true,
	}

	// If wildcard, disable AllowCredentials (because "*" + credentials = CORS error)
	if len(origins) == 1 && origins[0] == "*" {
		corsConfig.AllowAllOrigins = true
		corsConfig.AllowCredentials = false
	} else {
		corsConfig.AllowOrigins = origins
	}

	logger.InfoLogger.Info("CORS configured with origins: " + strings.Join(origins, ", "))
	return cors.New(corsConfig)
}
