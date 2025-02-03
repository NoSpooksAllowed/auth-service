package middleware

import (
	"context"
	"net/http"

	"github.com/NoSpooksAllowed/auth-service/jwtutil"
)

func AuthMiddleware(next http.Handler) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenString := r.Header.Get("Authorization")

		if tokenString == "" {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)

			return
		}

		tokenString = tokenString[len("Bearer "):]

		claims, err := jwtutil.ValidateJWT(tokenString)
		if err != nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)

			return
		}

		// Add the user ID to the request context
		ctx := context.WithValue(r.Context(), "userID", claims.UserID)
		r = r.WithContext(ctx)

		// Call the next handler
		next.ServeHTTP(w, r)
	})
}
