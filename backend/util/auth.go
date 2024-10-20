package util

import (
	"fmt"
	"os"

	"github.com/golang-jwt/jwt/v5"
)

func IsAuthenticated(authToken string, apiKey string) bool {
	if authToken != "" {
		token, err := jwt.Parse(authToken, func(token *jwt.Token) (any, error) {
			return []byte(os.Getenv("JWT_SECRET")), nil
		})

		if err != nil {
			fmt.Println("token invalid or expired:", err)
			return false
		}
		claims := token.Claims.(jwt.MapClaims)
		userId := claims["user_id"].(string)
	
		if userId != "" {
			return true
		}
	} else if apiKey != "" {
		// TODO: check api key in db / env
		return false
	}

	return false
}
