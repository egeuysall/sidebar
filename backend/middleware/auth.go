package middleware

import (
	"encoding/json"
	"net/http"

	"github.com/colecaccamise/go-backend/util"
)

func VerifyAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authToken, _ := r.Cookie("auth-token")
		apiKey := r.Header.Get("X-API-KEY")

		if authToken == nil && apiKey == "" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "unauthorized",
				"message": "missing token",
			})
			return
		}

		authenticated, _, err := util.IsAuthenticated(authToken, apiKey)
		if err != nil || !authenticated {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "unauthorized",
				"message": "token invalid or expired",
			})
			return
		}

		next.ServeHTTP(w, r)
	})
}
