package handlers

import (
	"log"
	"net/http"
	"strings"

	"github.com/Loryhoof/webserver/auth"
	"github.com/Loryhoof/webserver/types"
)

func VerifyTokenHandler(w http.ResponseWriter, r *http.Request) {
	
	authHeader := r.Header.Get("Authorization")
	token := strings.TrimPrefix(authHeader, "Bearer ")

	err := auth.VerifyJWT(token)

	if err != nil {
		log.Println("VerifyTokenHandler:", err)
		types.WriteError(w, http.StatusUnauthorized, "Unauthorized")
		return
	}

	types.WriteSuccess(w, "success")
}