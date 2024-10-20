package middleware

import (
	"fmt"
	"net/http"
)

func Affiliate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// read in "via" query param
		via := r.URL.Query().Get("via")

		fmt.Println("visitor refered by", via)

		// check db if affiliate exists

		// set affiliate cookie
		http.SetCookie(w, &http.Cookie{
			Name: "affiliate",
			Value: via,
			MaxAge: 60 * 60 * 24 * 30, // 30 days,
			HttpOnly: true,
		})

		next.ServeHTTP(w, r) 
	})
}