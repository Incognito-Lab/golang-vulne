package handlers

import (
	"fmt"
	"golang-vulne/database"
	"golang-vulne/middleware"
	"golang-vulne/models"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
)

// GetBalance returns user's current balance
// @Summary Get user balance
// @Description Get current user's account balance
// @Tags banking
// @Produce json
// @Security BearerAuth
// @Success 200 {object} map[string]interface{} "Balance information"
// @Failure 401 {object} map[string]string "Unauthorized"
// @Failure 404 {object} map[string]string "User not found"
// @Router /api/banking/balance [get]
func GetBalance(c *gin.Context) {
	userID, _ := c.Get("user_id")

	var user models.User
	if err := database.DB.First(&user, userID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"user_id":  user.ID,
		"balance":  user.Balance,
		"currency": "USD",
	})
}

// Deposit handles money deposits
// @Summary Deposit money
// @Description Add money to user's account
// @Tags banking
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param deposit body map[string]interface{} true "Deposit information"
// @Success 200 {object} map[string]interface{} "Deposit successful"
// @Failure 400 {object} map[string]string "Bad request"
// @Failure 401 {object} map[string]string "Unauthorized"
// @Router /api/banking/deposit [post]
func Deposit(c *gin.Context) {
	userID, _ := c.Get("user_id")

	var req struct {
		Amount      float64 `json:"amount" binding:"required,gt=0"`
		Description string  `json:"description"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Process deposit
	if err := database.UpdateUserBalance(userID.(uint), req.Amount, "deposit"); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to process deposit"})
		return
	}

	// Get updated balance
	var user models.User
	database.DB.First(&user, userID)

	c.JSON(http.StatusOK, gin.H{
		"message":     "Deposit successful",
		"amount":      req.Amount,
		"new_balance": user.Balance,
	})
}

// Withdraw handles money withdrawals
// @Summary Withdraw money
// @Description Withdraw money from user's account
// @Tags banking
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param withdrawal body map[string]interface{} true "Withdrawal information"
// @Success 200 {object} map[string]interface{} "Withdrawal successful"
// @Failure 400 {object} map[string]string "Bad request"
// @Failure 401 {object} map[string]string "Unauthorized"
// @Router /api/banking/withdraw [post]
func Withdraw(c *gin.Context) {
	userID, _ := c.Get("user_id")

	var req struct {
		Amount      float64 `json:"amount" binding:"required,gt=0"`
		Description string  `json:"description"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Get current user
	var user models.User
	if err := database.DB.First(&user, userID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	// Check balance
	if user.Balance < req.Amount {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Insufficient balance"})
		return
	}

	// Process withdrawal
	if err := database.UpdateUserBalance(userID.(uint), -req.Amount, "withdraw"); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to process withdrawal"})
		return
	}

	// Get updated balance
	database.DB.First(&user, userID)

	c.JSON(http.StatusOK, gin.H{
		"message":     "Withdrawal successful",
		"amount":      req.Amount,
		"new_balance": user.Balance,
	})
}

// Transfer handles money transfers between users
// @Summary Transfer money
// @Description Transfer money to another user
// @Tags banking
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param transfer body models.TransferRequest true "Transfer information"
// @Success 200 {object} map[string]interface{} "Transfer successful"
// @Failure 400 {object} map[string]string "Bad request"
// @Failure 401 {object} map[string]string "Unauthorized"
// @Router /api/banking/transfer [post]
func Transfer(c *gin.Context) {
	userID, _ := c.Get("user_id")

	var req models.TransferRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Prevent self-transfer
	if userID.(uint) == req.ToUserID {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Cannot transfer to yourself"})
		return
	}

	// Process transfer
	if err := database.TransferMoney(userID.(uint), req.ToUserID, req.Amount); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message":    "Transfer successful",
		"amount":     req.Amount,
		"to_user_id": req.ToUserID,
	})
}

// GetTransactions returns user's transaction history
// @Summary Get transaction history
// @Description Get user's transaction history with pagination
// @Tags banking
// @Produce json
// @Security BearerAuth
// @Param page query int false "Page number" default(1)
// @Param limit query int false "Items per page" default(10)
// @Success 200 {object} map[string]interface{} "Transaction history"
// @Failure 401 {object} map[string]string "Unauthorized"
// @Router /api/banking/transactions [get]
func GetTransactions(c *gin.Context) {
	userID, _ := c.Get("user_id")

	// Parse pagination parameters
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "10"))
	offset := (page - 1) * limit

	var transactions []models.Transaction
	var total int64

	// Get transactions for user
	database.DB.Model(&models.Transaction{}).Where("user_id = ?", userID).Count(&total)
	database.DB.Where("user_id = ?", userID).
		Preload("User").
		Preload("ToUser").
		Order("created_at DESC").
		Limit(limit).
		Offset(offset).
		Find(&transactions)

	c.JSON(http.StatusOK, gin.H{
		"transactions": transactions,
		"pagination": gin.H{
			"page":  page,
			"limit": limit,
			"total": total,
		},
	})
}

// GetUserTransactions returns transactions for any user (admin feature)
// @Summary Get user transactions (Admin)
// @Description Get transaction history for any user (admin only)
// @Tags banking
// @Produce json
// @Security BearerAuth
// @Param id path int true "User ID"
// @Param page query int false "Page number" default(1)
// @Param limit query int false "Items per page" default(10)
// @Success 200 {object} map[string]interface{} "Transaction history"
// @Failure 401 {object} map[string]string "Unauthorized"
// @Failure 403 {object} map[string]string "Forbidden"
// @Router /api/banking/transactions/{id} [get]
func GetUserTransactions(c *gin.Context) {
	targetUserID, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID"})
		return
	}

	// Check if user can access this data
	if !middleware.CheckUserAccess(c, uint(targetUserID)) {
		c.JSON(http.StatusForbidden, gin.H{"error": "Access denied"})
		return
	}

	// Parse pagination parameters
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "10"))
	offset := (page - 1) * limit

	var transactions []models.Transaction
	var total int64

	// Get transactions for target user
	database.DB.Model(&models.Transaction{}).Where("user_id = ?", targetUserID).Count(&total)
	database.DB.Where("user_id = ?", targetUserID).
		Preload("User").
		Preload("ToUser").
		Order("created_at DESC").
		Limit(limit).
		Offset(offset).
		Find(&transactions)

	c.JSON(http.StatusOK, gin.H{
		"user_id":      targetUserID,
		"transactions": transactions,
		"pagination": gin.H{
			"page":  page,
			"limit": limit,
			"total": total,
		},
	})
}

// SearchUsers searches for users by query
// @Summary Search users
// @Description Search for users by username, email, or role
// @Tags banking
// @Produce json
// @Security BearerAuth
// @Param q query string true "Search query"
// @Success 200 {object} map[string]interface{} "Search results"
// @Failure 400 {object} map[string]string "Bad request"
// @Failure 401 {object} map[string]string "Unauthorized"
// @Router /api/banking/search-users [get]
func SearchUsers(c *gin.Context) {
	query := c.Query("q")
	if query == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Search query required"})
		return
	}

	// Search users using database function
	users, err := database.SearchUsers(query)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Search failed"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"query": query,
		"users": users,
		"count": len(users),
	})
}

// GetAllUsers returns all users (admin only)
// @Summary Get all users (Admin)
// @Description Get list of all users (admin only)
// @Tags banking
// @Produce json
// @Security BearerAuth
// @Param page query int false "Page number" default(1)
// @Param limit query int false "Items per page" default(20)
// @Success 200 {object} map[string]interface{} "Users list"
// @Failure 401 {object} map[string]string "Unauthorized"
// @Failure 403 {object} map[string]string "Forbidden"
// @Router /api/banking/users [get]
func GetAllUsers(c *gin.Context) {
	// Parse pagination parameters
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "20"))
	offset := (page - 1) * limit

	var users []models.User
	var total int64

	// Get all users
	database.DB.Model(&models.User{}).Count(&total)
	database.DB.Order("created_at DESC").
		Limit(limit).
		Offset(offset).
		Find(&users)

	c.JSON(http.StatusOK, gin.H{
		"users": users,
		"pagination": gin.H{
			"page":  page,
			"limit": limit,
			"total": total,
		},
	})
}

// UpdateUserBalance allows admin to modify user balance
// @Summary Update user balance (Admin)
// @Description Update any user's balance (admin only)
// @Tags banking
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param id path int true "User ID"
// @Param balance body map[string]interface{} true "Balance update"
// @Success 200 {object} map[string]interface{} "Balance updated"
// @Failure 400 {object} map[string]string "Bad request"
// @Failure 401 {object} map[string]string "Unauthorized"
// @Failure 403 {object} map[string]string "Forbidden"
// @Router /api/banking/users/{id}/balance [put]
func UpdateUserBalance(c *gin.Context) {
	targetUserID, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID"})
		return
	}

	var req struct {
		Balance     float64 `json:"balance" binding:"required"`
		Description string  `json:"description"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Check access permission
	if !middleware.CheckUserAccess(c, uint(targetUserID)) {
		c.JSON(http.StatusForbidden, gin.H{"error": "Access denied"})
		return
	}

	var user models.User
	if err := database.DB.First(&user, targetUserID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	// Update balance directly
	oldBalance := user.Balance
	user.Balance = req.Balance

	if err := database.DB.Save(&user).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update balance"})
		return
	}

	// Create transaction record
	transaction := models.Transaction{
		UserID:      uint(targetUserID),
		Amount:      req.Balance - oldBalance,
		Type:        "admin_adjustment",
		Description: fmt.Sprintf("Admin balance adjustment: %s", req.Description),
	}
	database.DB.Create(&transaction)

	c.JSON(http.StatusOK, gin.H{
		"message":     "Balance updated successfully",
		"user_id":     targetUserID,
		"old_balance": oldBalance,
		"new_balance": req.Balance,
	})
}
