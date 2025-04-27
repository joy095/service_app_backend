package main

import (
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"

	"github.com/joy095/api-gateway/config"
	"github.com/joy095/api-gateway/logger"
	middleware "github.com/joy095/api-gateway/middlewares/cors"

	"github.com/gin-gonic/gin"
)

func init() {
	logger.InitLoggers()
	config.LoadEnv()
}

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
		logger.InfoLogger.Info("PORT not set. Using default: 8080")
	}

	router := gin.Default()
	router.Use(middleware.CorsMiddleware())

	router.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "ok from api-gateway"})
	})

	// Identity Service
	identityService := os.Getenv("IDENTITY_SERVICE_URL")

	// Image Service
	imageService := os.Getenv("IMAGE_SERVICE_URL")

	// Proxy routes
	router.Any("/v1/auth/*proxyPath", createProxyHandler(identityService, "/v1/auth"))
	router.Any("/v1/image/*proxyPath", createProxyHandler(imageService, "/v1/image"))

	logger.InfoLogger.Info("Starting HTTP server on port " + port)
	if err := router.Run(":" + port); err != nil {
		logger.ErrorLogger.Error("Failed to start server: " + err.Error())
		log.Fatal(err)
	}
}

// createProxyHandler sets up a proxy for a base target with correct path handling
func createProxyHandler(target string, prefix string) gin.HandlerFunc {
	return func(c *gin.Context) {
		targetURL, err := url.Parse(target)
		if err != nil {
			logger.ErrorLogger.Error("Failed to parse target URL: " + err.Error())
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Invalid target URL"})
			return
		}

		proxy := httputil.NewSingleHostReverseProxy(targetURL)

		originalDirector := proxy.Director
		proxy.Director = func(req *http.Request) {
			originalDirector(req)

			// Strip the API Gateway prefix and set real path
			proxyPath := strings.TrimPrefix(c.Request.URL.Path, prefix)
			req.URL.Path = proxyPath
			if !strings.HasPrefix(req.URL.Path, "/") {
				req.URL.Path = "/" + req.URL.Path
			}

			req.URL.RawQuery = c.Request.URL.RawQuery

			logger.InfoLogger.Infof("Proxying to: %s%s", target, req.URL.RequestURI())
		}

		proxy.ErrorHandler = func(rw http.ResponseWriter, req *http.Request, err error) {
			logger.ErrorLogger.Error("Proxy error: " + err.Error())
			c.JSON(http.StatusBadGateway, gin.H{"error": "Proxy request failed"})
		}

		proxy.ServeHTTP(c.Writer, c.Request)
	}
}
