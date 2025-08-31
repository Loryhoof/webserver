package handlers

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"github.com/Loryhoof/webserver/auth"
	"github.com/Loryhoof/webserver/db"
	"github.com/Loryhoof/webserver/types"
)

func ChangeNicknameHandler(w http.ResponseWriter, r *http.Request) {
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
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	email, err := auth.ParseJWT(token)

	if err != nil {
		panic(err)
	}

	type RequestData struct {
		Nickname string `json:"nickname"`
	}

	b, _ := io.ReadAll(r.Body)

	v := RequestData{}

	json.Unmarshal(b, &v)

	database := db.GetDB()

	_, err = database.Exec(`UPDATE users SET nickname = ? WHERE email = ?`, v.Nickname, email)

	if err != nil {
		w.WriteHeader(500)
		json.NewEncoder(w).Encode(types.ErrorResponse{Error: "Error when updating nickname"})
		return
	}


	w.WriteHeader(200)
	json.NewEncoder(w).Encode(types.SuccessResponse{Message: "ok"})
}