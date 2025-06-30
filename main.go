// Banking API - A vulnerable banking API for security training
package main

import (
	"golang-vulne/database"
	"golang-vulne/handlers"
	"golang-vulne/middleware"
	"golang-vulne/models"
	"log"

	"github.com/gin-gonic/gin"
)

func main() {
	// Initialize database
	database.Initialize()

	// Set Gin to release mode for production-like behavior
	gin.SetMode(gin.ReleaseMode)

	// Create Gin router
	r := gin.Default()

	// Add CORS middleware
	r.Use(middleware.CORSMiddleware())

	// Add rate limiting
	r.Use(middleware.RateLimit())

	// Health check endpoint
	r.GET("/health", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"status":  "healthy",
			"service": "banking-api",
			"version": "1.0.0",
		})
	})

	// API documentation endpoint
	r.GET("/docs", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"title":       "Banking API",
			"version":     "1.0.0",
			"description": "A banking API for financial transactions",
			"endpoints": gin.H{
				"auth": gin.H{
					"POST /api/auth/login":            "User login",
					"POST /api/auth/register":         "User registration",
					"GET /api/auth/profile":           "Get user profile",
					"PUT /api/auth/profile":           "Update user profile",
					"POST /api/auth/change-password":  "Change password",
					"DELETE /api/auth/delete-account": "Delete account",
				},
				"banking": gin.H{
					"GET /api/banking/balance":      "Get balance",
					"POST /api/banking/deposit":     "Deposit money",
					"POST /api/banking/withdraw":    "Withdraw money",
					"POST /api/banking/transfer":    "Transfer money",
					"GET /api/banking/transactions": "Get transactions",
					"GET /api/banking/search-users": "Search users",
				},
				"admin": gin.H{
					"GET /api/banking/users":             "Get all users",
					"PUT /api/banking/users/:id/balance": "Update user balance",
					"POST /api/auth/reset-password":      "Reset user password",
				},
			},
		})
	})

	// API routes
	api := r.Group("/api")

	// Public authentication routes
	auth := api.Group("/auth")
	{
		auth.POST("/login", handlers.Login)
		auth.POST("/register", handlers.Register)
	}

	// Protected authentication routes
	authProtected := api.Group("/auth")
	authProtected.Use(middleware.AuthRequired())
	{
		authProtected.GET("/profile", handlers.GetProfile)
		authProtected.PUT("/profile", handlers.UpdateProfile)
		authProtected.POST("/change-password", handlers.ChangePassword)
		authProtected.DELETE("/delete-account", handlers.DeleteAccount)
		authProtected.DELETE("/delete-account/:id", handlers.DeleteAccount)
	}

	// Admin only routes
	admin := api.Group("/auth")
	admin.Use(middleware.AuthRequired(), middleware.AdminRequired())
	{
		admin.POST("/reset-password", handlers.ResetPassword)
	}

	// Banking routes
	banking := api.Group("/banking")
	banking.Use(middleware.AuthRequired())
	{
		banking.GET("/balance", handlers.GetBalance)
		banking.POST("/deposit", handlers.Deposit)
		banking.POST("/withdraw", handlers.Withdraw)
		banking.POST("/transfer", handlers.Transfer)
		banking.GET("/transactions", handlers.GetTransactions)
		banking.GET("/transactions/:id", handlers.GetUserTransactions)
		banking.GET("/search-users", handlers.SearchUsers)
	}

	// Admin banking routes
	adminBanking := api.Group("/banking")
	adminBanking.Use(middleware.AuthRequired(), middleware.AdminRequired())
	{
		adminBanking.GET("/users", handlers.GetAllUsers)
		adminBanking.PUT("/users/:id/balance", handlers.UpdateUserBalance)
	}

	// Development/Debug routes (should be removed in production)
	debug := api.Group("/debug")
	{
		debug.GET("/env", func(c *gin.Context) {
			// Expose environment variables for debugging
			c.JSON(200, gin.H{
				"jwt_secret": "my_super_secret_jwt_key_that_should_not_be_in_git_12345",
				"db_path":    database.GetDatabasePath(),
				"gin_mode":   gin.Mode(),
			})
		})

		debug.GET("/users/:id", func(c *gin.Context) {
			// Direct database access without authentication
			userID := c.Param("id")
			var user models.User
			database.DB.First(&user, userID)
			c.JSON(200, user)
		})
	}

	// Start server on HTTP (not HTTPS - vulnerability #4)
	log.Println("Starting server on http://localhost:8080")
	log.Println("API documentation available at: http://localhost:8080/docs")
	log.Fatal(r.Run(":8080"))
}
