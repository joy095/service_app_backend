package main

import (
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/joy095/word-filter/badwords"
	"github.com/joy095/word-filter/config"
	"github.com/joy095/word-filter/logger"

	"github.com/gin-gonic/gin"
)

func init() {
	logger.InitLoggers()

	config.LoadEnv()
}

func main() {
	// Set up Gin router
	router := gin.Default()

	// Step 1: Load bad words from a text file
	badwords.LoadBadWords("badwords/en.txt")

	logger.InfoLogger.Info("Bad words loaded successfully!")

	fmt.Println("Bad words loaded successfully!")

	port := os.Getenv("PORT")
	if port == "" {
		port = "8082"
	}

	// Keep only the essential endpoint for checking bad words
	router.POST("/check", func(c *gin.Context) {
		logger.InfoLogger.Info("Check route hit")

		var request badwords.BadWordRequest

		if err := c.ShouldBindJSON(&request); err != nil {
			logger.ErrorLogger.Error(err.Error())

			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		// Use the updated CheckText function to check for bad words
		response := badwords.CheckText(request.Text)
		c.JSON(http.StatusOK, response)
	})

	// Health check endpoint (keeping this as it's a good practice)
	router.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "ok"})
	})

	// Start the Gin server directly
	serverAddr := ":" + port
	logger.InfoLogger.Info("Starting HTTP server on " + serverAddr)
	log.Println("Starting HTTP server on " + serverAddr)

	if err := router.Run(serverAddr); err != nil {
		logger.ErrorLogger.Errorf("Failed to start server: %v", err)
		log.Fatalf("Failed to start server: %v", err)
	}
}
