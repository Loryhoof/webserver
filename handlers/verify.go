package handlers

import (
	"encoding/json"
	"fmt"
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
		fmt.Println(err)

		w.WriteHeader(401)
		json.NewEncoder(w).Encode(types.ErrorResponse{Error: "Unauthorized"})
		return
	}

	w.WriteHeader(200)
	json.NewEncoder(w).Encode(types.SuccessResponse{Message: "valid jwt"})
}