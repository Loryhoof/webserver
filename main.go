package main

import (
	"fmt"
	"net/http"
	"sync"

	_ "github.com/mattn/go-sqlite3"

	"github.com/Loryhoof/webserver/db"
	"github.com/Loryhoof/webserver/handlers"
	"github.com/Loryhoof/webserver/middleware"
	"github.com/Loryhoof/webserver/models"
)

func main() {

	db.Init("./chat.db")
	defer db.Close()

	clients := make(map[string]*models.Client)
	messages := []models.Message{}

	var clientsMu sync.Mutex
	var messagesMu sync.Mutex

	fmt.Println("Server running on port 8080")

	mux := http.NewServeMux()

	mux.Handle("/ws", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlers.WebsocketHandler(w, r, clients, &messages, &clientsMu, &messagesMu)
	}))

	mux.Handle("/verify-token", http.HandlerFunc(handlers.VerifyTokenHandler))
	mux.Handle("/login", http.HandlerFunc(handlers.LoginHandler))
	mux.Handle("/register", http.HandlerFunc(handlers.RegisterHandler))
	mux.Handle("/refresh-token", http.HandlerFunc(handlers.RefreshTokenHandler))
	mux.Handle("/change-nickname", http.HandlerFunc(handlers.ChangeNicknameHandler))

	http.ListenAndServe(`:8080`, middleware.Cors(mux))
}
