package auth

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"

	"github.com/joy095/identity/config/db"
	"github.com/joy095/identity/logger"
	"github.com/joy095/identity/models"
	"github.com/joy095/identity/utils/jwt_parse"

	"github.com/gin-gonic/gin"
)

// AuthMiddleware checks the authentication of the request using JWT token.
func AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Parse and validate JWT token using the ParseJWTToken function
		jwt_parse.ParseJWTToken()(c)

		// Retrieve user_id from the context (set by ParseJWTToken)
		userIDFromToken, exists := c.Get("user_id")
		if !exists {
			logger.ErrorLogger.Error("User ID not found in context")
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
			c.Abort()
			return
		}

		usernameParam := c.Param("username")
		// Check if the user_id from the token matches the username parameter
		rawBody, _ := c.GetRawData()
		c.Request.Body = io.NopCloser(bytes.NewBuffer(rawBody)) // allow re-reading

		var body struct {
			UserID string `json:"user_id"`
		}
		json.Unmarshal(rawBody, &body)

		if usernameParam == "" && body.UserID == "" {
			logger.ErrorLogger.Error("Either 'username' param or 'user_id' in body is required")
			c.JSON(http.StatusBadRequest, gin.H{"error": "Either 'username' param or 'user_id' in body is required"})
			c.Abort()
			return
		}

		// If username is provided, fetch user and match token user_id
		if usernameParam != "" {
			user, err := models.GetUserByUsername(db.DB, usernameParam)
			if err != nil {
				logger.ErrorLogger.Errorf("User not found by username: %s", usernameParam)
				c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
				c.Abort()
				return
			}

			if user.ID.String() != userIDFromToken {
				logger.ErrorLogger.Errorf("User ID mismatch: token(%s) vs db(%s)", userIDFromToken, user.ID)
				c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized access"})
				c.Abort()
				return
			}

			logger.InfoLogger.Infof("Authenticated via username: %s", user.Username)
		}

		// If user_id from body is provided, ensure it matches token
		if body.UserID != "" && body.UserID != userIDFromToken {
			logger.ErrorLogger.Errorf("User ID mismatch: token(%s) vs body(%s)", userIDFromToken, body.UserID)
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized access"})
			c.Abort()
			return
		}

		// Attach user_id to context for downstream handlers
		c.Set("user_id", userIDFromToken)
		logger.InfoLogger.Infof("Authenticated user_id: %s", userIDFromToken)
		c.Next()
	}
}
