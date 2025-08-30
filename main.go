package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/bcrypt"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"
)

var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
	CheckOrigin: func(r *http.Request) bool {
		return true // allow all reqs
	},
}

type Client struct {
	ID         string
	Connection *websocket.Conn
}

type ErrorResponse struct {
	Error string `json:"error"`
}

type SuccessResponse struct {
	Message string `json:"message"`
}

type TokenResponse struct {
	AccessToken  string `json:"accessToken"`
	RefreshToken string `json:"refreshToken"`
}

type RefreshToken struct {
	UserID int `json:"userID"`
	Token  string `json:"token"`
	Expiry int64 `json:"expiry"`
}

var clients = make(map[string]Client)

type Message struct {
	ID      string `json:"id"`
	Message string `json:"message"`
}

var messages []Message

var jwtSecret = []byte("1e2e894f1b997c8a92e577a7e9f6a30e805cd53b")

func wsHandler(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)

	if err != nil {
		fmt.Println(err)
		return
	}

	id := uuid.NewString()

	client := Client{ID: id, Connection: conn}
	clients[id] = client
	fmt.Printf("Client connected: %v", client.ID)

	conn.SetCloseHandler(func(code int, text string) error {
		fmt.Println("\nClient sent close frame:", id, "Code:", code, "Text:", text)
		delete(clients, id)

		return nil
	})

	conn.WriteJSON(messages)

	// conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	// conn.SetPongHandler(func(string) error {
	// 	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	// 	return nil
	// })

	defer conn.Close()

	for {
		_, b, err := conn.ReadMessage()

		if err != nil {
			fmt.Println(err)
			return
		}

		type IncomingMessage struct {
			Event   string `json:"event"`
			Message string `json:"message"`
		}

		var e IncomingMessage

		json.Unmarshal(b, &e)

		messages = append(messages, Message{ID: id, Message: e.Message})

		type OutgoingMessage struct {
			Type    string `json:"type"`
			ID      string `json:"id"`
			Message string `json:"message"`
		}

		fmt.Println(string(b))
		v := OutgoingMessage{Type: "message", ID: id, Message: e.Message}

		//conn.WriteJSON(v)

		// broadcast? maybe?
		for _, client := range clients {
			err := client.Connection.WriteJSON(v)

			if err != nil {
				fmt.Println("write error, removing client:", client.ID, err)
				client.Connection.Close()
				delete(clients, client.ID)
			}

		}
	}
}

func createJWT(username string) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"username": username,
		"exp":      time.Now().Add(15 * time.Minute).Unix(),
	})

	tokenString, err := token.SignedString(jwtSecret)

	if err != nil {
		return "", err
	}

	return tokenString, nil
}

func verifyJWT(tokenString string) error {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (any, error) {
		return jwtSecret, nil
	})

	if err != nil {
		return err
	}

	if !token.Valid {
		return fmt.Errorf("invalid token")
	}

	return nil
}

func refreshTokenHandler(w http.ResponseWriter, r *http.Request) {

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
		RefreshToken string `json:"refreshToken"`
	}

	b, err := io.ReadAll(r.Body)

	if err != nil {
		fmt.Println(err)
		return
	}

	v := Data{}

	json.Unmarshal(b, &v)

	db, err := sql.Open("sqlite3", "chat.db")

	if err != nil {
		panic(err)
	}

	defer db.Close()

	var userID int
	var expiry int64

	row := db.QueryRow(`SELECT user_id, expiry FROM refresh_tokens WHERE token = ?`, v.RefreshToken)
	err = row.Scan(&userID, &expiry)

	if err == sql.ErrNoRows {
		fmt.Println(err)

		w.WriteHeader(401)
		json.NewEncoder(w).Encode(ErrorResponse{Error: "No refresh token found"})
		return
	}

	if err != nil {
		fmt.Println(err)
		return
	}

	valid := expiry > time.Now().Unix()

	if valid {
		var email string
		row := db.QueryRow(`SELECT email FROM users WHERE id = ?`, userID)
		err = row.Scan(&email)

		if err == sql.ErrNoRows {
			panic(err)
		}

		accessToken, err := createJWT(email)

		if err != nil {
			panic(err)
		}

		db.Exec(`DELETE FROM refresh_tokens WHERE token = ?`, v.RefreshToken)

		refreshToken := RefreshToken{UserID: userID, Token: uuid.NewString(), Expiry: time.Now().Add(time.Hour * 24 * 7).Unix()}

		db.Exec(`INSERT INTO refresh_tokens (user_id, token, expiry) VALUES (?, ?, ?)`, refreshToken.UserID, refreshToken.Token, refreshToken.Expiry)

		w.WriteHeader(200)
		json.NewEncoder(w).Encode(TokenResponse{AccessToken: accessToken, RefreshToken: refreshToken.Token})
	} else {
		w.WriteHeader(401)
		json.NewEncoder(w).Encode(ErrorResponse{Error: "refresh token expired"})
	}
}

func verifyTokenHandler(w http.ResponseWriter, r *http.Request) {
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

	err := verifyJWT(token)

	if err != nil {
		fmt.Println(err)

		w.WriteHeader(401)
		json.NewEncoder(w).Encode(ErrorResponse{Error: "Unauthorized"})
		return
	}

	w.WriteHeader(200)
	json.NewEncoder(w).Encode(SuccessResponse{Message: "valid jwt"})
}

func registerHandler(w http.ResponseWriter, r *http.Request) {
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

	db, err := sql.Open("sqlite3", "./chat.db")

	if err != nil {
		panic(err)
	}

	defer db.Close()

	pwd, err := bcrypt.GenerateFromPassword([]byte(v.Password), bcrypt.DefaultCost)

	if err != nil {
		panic(err)
	}

	_, err = db.Exec(`INSERT INTO users (email, password_hash) VALUES (?, ?)`, v.Email, string(pwd))

	if err != nil {
		fmt.Println(err)
		w.WriteHeader(500)
		json.NewEncoder(w).Encode(ErrorResponse{Error: "Internal error when registering"})
		return
	}

	w.WriteHeader(200)
	json.NewEncoder(w).Encode(SuccessResponse{Message: "success"})
}

func loginHandler(w http.ResponseWriter, r *http.Request) {

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

	db, err := sql.Open("sqlite3", "./chat.db")

	if err != nil {
		panic(err)
	}

	defer db.Close()

	var userID int
	var passwordHash string

	row := db.QueryRow(`SELECT id, password_hash FROM users WHERE email = ?`, u.Email)
	err = row.Scan(&userID, &passwordHash)

	if err == sql.ErrNoRows {

		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(ErrorResponse{Error: "Invalid email or password"})
		return
	}

	err = bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(u.Password))

	if err != nil {
		w.WriteHeader(401)
		json.NewEncoder(w).Encode(ErrorResponse{Error: "Invalid password"})
		return
	}

	accTkn, err := createJWT(u.Email)

	if err != nil {
		fmt.Println("Error with jwt token creation", err)
		w.WriteHeader(500)
		json.NewEncoder(w).Encode(ErrorResponse{Error: "Something went wrong"})
		return
	}

	expiry := time.Now().Add(time.Hour * 24 * 7).UTC().Unix() // 7 days
	refTkn := RefreshToken{UserID: userID, Token: uuid.NewString(), Expiry: expiry}

	_, err = db.Exec(`INSERT INTO refresh_tokens (user_id, token, expiry) VALUES (?, ?, ?)`, refTkn.UserID, refTkn.Token, refTkn.Expiry)

	if err != nil {
		fmt.Println(err)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(TokenResponse{AccessToken: accTkn, RefreshToken: refTkn.Token})
}

func main() {

	db, err := sql.Open("sqlite3", "./chat.db")

	if err != nil {
		panic(err)
	}

	defer db.Close()

	db.Exec(`CREATE TABLE IF NOT EXISTS users (
		id INTEGER PRIMARY KEY AUTOINCREMENT, -- unique number
		email TEXT UNIQUE NOT NULL,        -- login name
		password_hash TEXT NOT NULL,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	);
	`)

	db.Exec(`CREATE TABLE IF NOT EXISTS refresh_tokens (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		user_id INT NOT NULL,
		token TEXT NOT NULL UNIQUE,
		expiry INTEGER NOT NULL,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	);
	`)

	rows, _ := db.Query("SELECT * FROM users")

	for rows.Next() {
		var id int
		var email string
		var passwordHash string
		var createdAt string

		rows.Scan(&id, &email, &passwordHash, &createdAt)
		fmt.Println(id, email, passwordHash, createdAt)
	}

	fmt.Println("Server running on port 8080")

	// http.HandleFunc("/ws", wsHandler)

	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/register", registerHandler)
	http.HandleFunc("/verify-token", verifyTokenHandler)
	http.HandleFunc("/refresh-token", refreshTokenHandler)
	http.ListenAndServe(`:8080`, nil)
}
