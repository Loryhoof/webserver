package handlers

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/Loryhoof/webserver/auth"
	"github.com/Loryhoof/webserver/db"
	"github.com/Loryhoof/webserver/models"
	"github.com/Loryhoof/webserver/types"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

func RegisterHandler(w http.ResponseWriter, r *http.Request) {
	// preflight req (?)
	if r.Method == http.MethodOptions {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		w.WriteHeader(http.StatusOK)
		return
	}

	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Content-Type", "application/json")

	type Data struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	data, err := io.ReadAll(r.Body)

	if err != nil {
		fmt.Println(err)
		return
	}

	v := Data{}

	json.Unmarshal(data, &v)

	database := db.GetDB()

	pwd, err := bcrypt.GenerateFromPassword([]byte(v.Password), bcrypt.DefaultCost)

	if err != nil {
		panic(err)
	}

	_, err = database.Exec(`INSERT INTO users (email, password_hash) VALUES (?, ?)`, v.Email, string(pwd))

	if err != nil {
		fmt.Println(err)
		w.WriteHeader(500)
		json.NewEncoder(w).Encode(types.ErrorResponse{Error: "Internal error when registering"})
		return
	}

	w.WriteHeader(200)
	json.NewEncoder(w).Encode(types.SuccessResponse{Message: "success"})
}

func LoginHandler(w http.ResponseWriter, r *http.Request) {

	// preflight req (?)
	if r.Method == http.MethodOptions {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		w.WriteHeader(http.StatusOK)
		return
	}

	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Content-Type", "application/json")

	type Data struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	data, err := io.ReadAll(r.Body)

	if err != nil {
		fmt.Println(err)
		return
	}

	u := Data{}
	json.Unmarshal(data, &u)

	database := db.GetDB()

	var userID int
	var passwordHash string

	row := database.QueryRow(`SELECT id, password_hash FROM users WHERE email = ?`, u.Email)
	err = row.Scan(&userID, &passwordHash)

	if err == sql.ErrNoRows {

		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(types.ErrorResponse{Error: "Invalid email or password"})
		return
	}

	err = bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(u.Password))

	if err != nil {
		w.WriteHeader(401)
		json.NewEncoder(w).Encode(types.ErrorResponse{Error: "Invalid password"})
		return
	}

	accTkn, err := auth.CreateJWT(u.Email)

	if err != nil {
		fmt.Println("Error with jwt token creation", err)
		w.WriteHeader(500)
		json.NewEncoder(w).Encode(types.ErrorResponse{Error: "Something went wrong"})
		return
	}

	expiry := time.Now().Add(time.Hour * 24 * 7).UTC().Unix() // 7 days
	refTkn := models.RefreshToken{UserID: userID, Token: uuid.NewString(), Expiry: expiry}

	_, err = database.Exec(`INSERT INTO refresh_tokens (user_id, token, expiry) VALUES (?, ?, ?)`, refTkn.UserID, refTkn.Token, refTkn.Expiry)

	if err != nil {
		fmt.Println(err)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(types.TokenResponse{AccessToken: accTkn, RefreshToken: refTkn.Token})
}