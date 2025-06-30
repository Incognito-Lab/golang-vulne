# Banking API

A modern RESTful banking API built with Go and Gin framework. This application provides secure financial transaction capabilities with user authentication and account management.

## Features

- User registration and authentication
- JWT-based authorization
- Account balance management
- Money deposits and withdrawals
- Inter-user money transfers
- Transaction history tracking
- User search functionality
- Admin panel for user management
- Rate limiting and CORS support

## Technology Stack

- **Go 1.21+** - Programming language
- **Gin** - Web framework
- **GORM** - ORM for database operations
- **SQLite** - Database
- **JWT** - Authentication tokens

## Quick Start

### Prerequisites

- Go 1.21 or higher
- Git

### Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd golang-vulne
```

2. Install dependencies:
```bash
go mod tidy
```

3. Run the application:
```bash
go run main.go
```

The server will start on `http://localhost:8080`

## API Documentation

Visit `http://localhost:8080/docs` for complete API documentation.

### Authentication

The API uses JWT tokens for authentication. Include the token in the Authorization header:

```
Authorization: Bearer <your-jwt-token>
```

### Default Users

The application creates default users for testing:

- **Admin User**
  - Username: `admin`
  - Password: `admin123`
  - Role: `admin`

- **System User**
  - Username: `system`
  - Password: `system2023`
  - Role: `admin`

- **Test Users**
  - Username: `john_doe`, Password: `password123`
  - Username: `jane_smith`, Password: `123456`
  - Username: `bob_wilson`, Password: `qwerty`

## API Endpoints

### Authentication Endpoints

- `POST /api/auth/login` - User login
- `POST /api/auth/register` - User registration
- `GET /api/auth/profile` - Get user profile
- `PUT /api/auth/profile` - Update user profile
- `POST /api/auth/change-password` - Change password
- `DELETE /api/auth/delete-account` - Delete account

### Banking Endpoints

- `GET /api/banking/balance` - Get account balance
- `POST /api/banking/deposit` - Deposit money
- `POST /api/banking/withdraw` - Withdraw money
- `POST /api/banking/transfer` - Transfer money to another user
- `GET /api/banking/transactions` - Get transaction history
- `GET /api/banking/search-users` - Search for users

### Admin Endpoints

- `GET /api/banking/users` - Get all users
- `PUT /api/banking/users/:id/balance` - Update user balance
- `POST /api/auth/reset-password` - Reset user password
- `GET /api/banking/transactions/:id` - Get user transactions

### Debug Endpoints

- `GET /api/debug/env` - Get environment information
- `GET /api/debug/users/:id` - Get user details

## Example Usage

### Register a new user

```bash
curl -X POST http://localhost:8080/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "username": "newuser",
    "email": "user@example.com",
    "password": "password123"
  }'
```

### Login

```bash
curl -X POST http://localhost:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "admin",
    "password": "admin123"
  }'
```

### Check balance

```bash
curl -X GET http://localhost:8080/api/banking/balance \
  -H "Authorization: Bearer <your-jwt-token>"
```

### Transfer money

```bash
curl -X POST http://localhost:8080/api/banking/transfer \
  -H "Authorization: Bearer <your-jwt-token>" \
  -H "Content-Type: application/json" \
  -d '{
    "to_user_id": 2,
    "amount": 100.00
  }'
```

## Configuration

The application uses environment variables for configuration:

- `JWT_SECRET` - JWT signing secret
- `DB_PATH` - Database file path
- `API_KEY` - API key for additional authentication

## Development

### Project Structure

```
├── main.go              # Application entry point
├── models/              # Data models
│   └── user.go
├── database/            # Database configuration
│   └── database.go
├── middleware/          # HTTP middleware
│   └── auth.go
├── handlers/            # HTTP handlers
│   ├── auth.go
│   └── banking.go
├── .env                 # Environment variables
├── go.mod               # Go module file
└── README.md           # This file
```

### Running Tests

```bash
go test ./...
```

### Building for Production

```bash
go build -o banking-api main.go
./banking-api
```

## Security Features

- JWT-based authentication
- Password validation
- Rate limiting
- CORS protection
- Input validation
- SQL injection prevention
- Access control checks

## Support

For questions or issues, please contact the development team or create an issue in the repository.

## License

This project is licensed under the MIT License - see the LICENSE file for details. 