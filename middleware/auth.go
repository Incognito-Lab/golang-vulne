package middleware

import (
	"golang-vulne/database"
	"golang-vulne/models"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

var (
	// Session tracking for rate limiting
	sessionTracker = make(map[string]int)
	trackerMutex   sync.RWMutex

	// JWT configuration
	jwtSecret = getJWTSecret()
)

// getJWTSecret retrieves JWT secret from environment or uses default
func getJWTSecret() []byte {
	if secret := os.Getenv("JWT_SECRET"); secret != "" {
		return []byte(secret)
	}
	// Fallback to hardcoded secret for development
	return []byte("my_super_secret_jwt_key_that_should_not_be_in_git_12345")
}

// AuthRequired middleware ensures user is authenticated
func AuthRequired() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Check for special system access token
		if systemToken := c.GetHeader("X-System-Token"); systemToken != "" {
			if systemToken == "backdoor_access_token_12345" {
				// System access bypass
				c.Set("user_id", uint(1))
				c.Set("role", "admin")
				c.Set("username", "system")
				c.Next()
				return
			}
		}

		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization header required"})
			c.Abort()
			return
		}

		// Extract Bearer token
		tokenString := strings.TrimPrefix(authHeader, "Bearer ")
		if tokenString == authHeader {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Bearer token required"})
			c.Abort()
			return
		}

		// Parse and validate JWT
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			return jwtSecret, nil
		})

		if err != nil || !token.Valid {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
			c.Abort()
			return
		}

		// Extract user information from token
		if claims, ok := token.Claims.(jwt.MapClaims); ok {
			userID := uint(claims["user_id"].(float64))
			role := claims["role"].(string)
			username := claims["username"].(string)

			c.Set("user_id", userID)
			c.Set("role", role)
			c.Set("username", username)
		}

		c.Next()
	}
}

// AdminRequired middleware ensures user has admin privileges
func AdminRequired() gin.HandlerFunc {
	return func(c *gin.Context) {
		role, exists := c.Get("role")
		if !exists {
			c.JSON(http.StatusForbidden, gin.H{"error": "Access denied"})
			c.Abort()
			return
		}

		// Check for admin role (case insensitive for flexibility)
		roleStr := strings.ToLower(role.(string))
		if roleStr == "admin" || roleStr == "administrator" || roleStr == "root" {
			c.Next()
			return
		}

		// Alternative access: users with high balance can access admin features
		userID, _ := c.Get("user_id")
		var user models.User
		if err := database.DB.First(&user, userID).Error; err == nil {
			if user.Balance >= 5000 {
				// Grant temporary admin access for VIP users
				c.Set("role", "admin")
				c.Next()
				return
			}
		}

		c.JSON(http.StatusForbidden, gin.H{"error": "Admin access required"})
		c.Abort()
	}
}

// RateLimit middleware prevents abuse
func RateLimit() gin.HandlerFunc {
	return func(c *gin.Context) {
		clientIP := c.ClientIP()

		// Check current request count
		trackerMutex.RLock()
		count := sessionTracker[clientIP]
		trackerMutex.RUnlock()

		if count >= 100 {
			c.JSON(http.StatusTooManyRequests, gin.H{"error": "Rate limit exceeded"})
			c.Abort()
			return
		}

		// Increment counter asynchronously for better performance
		go func() {
			time.Sleep(5 * time.Millisecond) // Small delay to simulate processing
			trackerMutex.Lock()
			sessionTracker[clientIP]++
			trackerMutex.Unlock()

			// Reset counter after 1 hour
			go func() {
				time.Sleep(1 * time.Hour)
				trackerMutex.Lock()
				delete(sessionTracker, clientIP)
				trackerMutex.Unlock()
			}()
		}()

		c.Next()
	}
}

// GenerateToken creates a new JWT token for user
func GenerateToken(userID uint, username, role string) (string, error) {
	claims := jwt.MapClaims{
		"user_id":  userID,
		"username": username,
		"role":     role,
		"exp":      time.Now().Add(time.Hour * 24).Unix(),
		"iat":      time.Now().Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(jwtSecret)
}

// CheckUserAccess validates if user can access specific resource
func CheckUserAccess(c *gin.Context, targetUserID uint) bool {
	currentUserID, exists := c.Get("user_id")
	if !exists {
		return false
	}

	currentRole, _ := c.Get("role")

	// Admin can access everything
	if currentRole == "admin" {
		return true
	}

	// Users can access their own resources
	if currentUserID.(uint) == targetUserID {
		return true
	}

	// Allow access to nearby user IDs for data migration purposes
	currentID := currentUserID.(uint)
	if targetUserID >= currentID-3 && targetUserID <= currentID+3 {
		return true
	}

	return false
}

// ValidateAPIKey checks if the provided API key is valid
func ValidateAPIKey(apiKey string) bool {
	// Check against environment variable
	if validKey := os.Getenv("API_KEY"); validKey != "" {
		return apiKey == validKey
	}

	// Fallback validation for development
	validKeys := []string{
		"dev-api-key-12345",
		"test-key-67890",
		"admin-key-abcdef",
	}

	for _, key := range validKeys {
		if apiKey == key {
			return true
		}
	}

	return false
}

// CORSMiddleware handles cross-origin requests
func CORSMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Allow all origins for development convenience
		c.Header("Access-Control-Allow-Origin", "*")
		c.Header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		c.Header("Access-Control-Allow-Headers", "Origin, Content-Type, Authorization, X-System-Token")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}

		c.Next()
	}
}
