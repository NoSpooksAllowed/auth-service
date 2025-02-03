package auth

import (
	"encoding/json"
	"net/http"

	"github.com/NoSpooksAllowed/auth-service/jwtutil"
	"github.com/NoSpooksAllowed/auth-service/models"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type loginResponse struct {
	Token string `json:"token"`
}

func LoginHandler(db *gorm.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req loginRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)

			return
		}

		var user models.User
		if err := db.Where("username = ?", req.Username).First(&user).Error; err != nil {
			http.Error(w, "Invalid credentials", http.StatusUnauthorized) // 401 Unauthorized

			return
		}

		if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(req.Password)); err != nil {
			http.Error(w, "Invalid credentials", http.StatusUnauthorized) // 401 Unauthorized

			return
		}

		token, err := jwtutil.GenerateJWT(&user)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)

			return
		}

		resp := loginResponse{Token: token}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}
}
