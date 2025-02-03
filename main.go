package main

import (
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/NoSpooksAllowed/auth-service/auth"
	"github.com/NoSpooksAllowed/auth-service/middleware"
	"github.com/NoSpooksAllowed/auth-service/models"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

func main() {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		log.Fatal("DATABASE_URL environment variable not set")
	}

	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		log.Fatal("Failed to connect to database:", err)
	}

	// AutoMigrate will create the users table if it doesn't exists.
	err = db.AutoMigrate(&models.User{})
	if err != nil {
		log.Fatal("Failed to migrate database", err)
	}

	r := chi.NewRouter()

	r.Post("/signup", auth.SignupHandler(db))
	r.Post("/login", auth.LoginHandler(db))

	r.Get(
		"/protected",
		middleware.AuthMiddleware(http.HandlerFunc(protectedHandler)),
	) // Protected endpoint

	log.Println("Starting server on :8080")
	err = http.ListenAndServe(":8080", r)
	if err != nil {
		log.Fatal("Error starting server: ", err)
	}
}

func protectedHandler(w http.ResponseWriter, r *http.Request) {
	userID := r.Context().Value("userID").(uuid.UUID) // Retrieve user ID from context

	w.Write([]byte(fmt.Sprintf("Protected resource accessed by user: %v", userID)))
}
