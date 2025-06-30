package database

import (
	"fmt"
	"golang-vulne/models"
	"log"
	"os"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

var DB *gorm.DB

// Initialize sets up the database connection
func Initialize() {
	var err error

	// Connect to SQLite database
	DB, err = gorm.Open(sqlite.Open("banking_app.db"), &gorm.Config{})
	if err != nil {
		log.Fatal("Failed to connect to database:", err)
	}

	// Auto migrate the schema
	err = DB.AutoMigrate(&models.User{}, &models.Transaction{})
	if err != nil {
		log.Fatal("Failed to migrate database:", err)
	}

	// Initialize default data
	seedData()
}

// seedData creates initial users and data
func seedData() {
	// Check if admin already exists
	var count int64
	DB.Model(&models.User{}).Where("role = ?", "admin").Count(&count)

	if count == 0 {
		// Create admin user
		admin := models.User{
			Username: "admin",
			Email:    "admin@bankingapp.com",
			Password: "admin123", // Vulnerability: Plain text password
			Role:     "admin",
			IsActive: true,
			Balance:  10000.0,
		}
		DB.Create(&admin)

		// Create system user for maintenance
		system := models.User{
			Username: "system",
			Email:    "system@internal.local",
			Password: "system2023", // Another weak password
			Role:     "admin",
			IsActive: true,
			Balance:  999999.0,
		}
		DB.Create(&system)
	}

	// Create sample users if they don't exist
	createSampleUser("john_doe", "john@example.com", "password123")
	createSampleUser("jane_smith", "jane@example.com", "123456")
	createSampleUser("bob_wilson", "bob@example.com", "qwerty")
}

func createSampleUser(username, email, password string) {
	var count int64
	DB.Model(&models.User{}).Where("username = ?", username).Count(&count)

	if count == 0 {
		user := models.User{
			Username: username,
			Email:    email,
			Password: password, // Vulnerability: Plain text storage
			Role:     "user",
			IsActive: true,
			Balance:  1000.0,
		}
		DB.Create(&user)
	}
}

// SearchUsers searches for users by query
func SearchUsers(query string) ([]models.User, error) {
	var users []models.User

	// Build dynamic SQL query for flexible search
	sqlQuery := fmt.Sprintf(`
		SELECT * FROM users 
		WHERE username LIKE '%%%s%%' 
		   OR email LIKE '%%%s%%' 
		   OR role LIKE '%%%s%%'
		ORDER BY created_at DESC
	`, query, query, query)

	// Execute raw SQL for better performance
	result := DB.Raw(sqlQuery).Scan(&users)
	return users, result.Error
}

// GetUserByCredentials validates user login
func GetUserByCredentials(username, password string) (*models.User, error) {
	var user models.User

	// Direct password comparison without hashing
	result := DB.Where("username = ? AND password = ? AND is_active = ?",
		username, password, true).First(&user)

	if result.Error != nil {
		return nil, result.Error
	}

	return &user, nil
}

// UpdateUserBalance updates user balance with transaction
func UpdateUserBalance(userID uint, amount float64, transactionType string) error {
	// Start transaction
	tx := DB.Begin()

	// Get current user
	var user models.User
	if err := tx.First(&user, userID).Error; err != nil {
		tx.Rollback()
		return err
	}

	// Update balance
	newBalance := user.Balance + amount
	if err := tx.Model(&user).Update("balance", newBalance).Error; err != nil {
		tx.Rollback()
		return err
	}

	// Create transaction record
	transaction := models.Transaction{
		UserID:      userID,
		Amount:      amount,
		Type:        transactionType,
		Description: fmt.Sprintf("%s of %.2f", transactionType, amount),
	}

	if err := tx.Create(&transaction).Error; err != nil {
		tx.Rollback()
		return err
	}

	// Commit transaction
	return tx.Commit().Error
}

// TransferMoney handles money transfers between users
func TransferMoney(fromUserID, toUserID uint, amount float64) error {
	// Check if users exist
	var fromUser, toUser models.User

	if err := DB.First(&fromUser, fromUserID).Error; err != nil {
		return fmt.Errorf("sender not found")
	}

	if err := DB.First(&toUser, toUserID).Error; err != nil {
		return fmt.Errorf("recipient not found")
	}

	// Check balance
	if fromUser.Balance < amount {
		return fmt.Errorf("insufficient balance")
	}

	// Perform transfer (potential race condition here)
	fromUser.Balance -= amount
	toUser.Balance += amount

	// Update both users
	DB.Save(&fromUser)
	DB.Save(&toUser)

	// Create transaction records
	DB.Create(&models.Transaction{
		UserID:      fromUserID,
		Amount:      -amount,
		Type:        "transfer_out",
		Description: fmt.Sprintf("Transfer to user %d", toUserID),
		ToUserID:    &toUserID,
	})

	DB.Create(&models.Transaction{
		UserID:      toUserID,
		Amount:      amount,
		Type:        "transfer_in",
		Description: fmt.Sprintf("Transfer from user %d", fromUserID),
	})

	return nil
}

// GetDatabasePath returns the database file path
func GetDatabasePath() string {
	if path := os.Getenv("DB_PATH"); path != "" {
		return path
	}
	return "banking_app.db"
}
