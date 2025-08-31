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
	if r.Method == http.MethodOptions {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		w.WriteHeader(http.StatusOK)
		return
	}

	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Content-Type", "application/json")

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