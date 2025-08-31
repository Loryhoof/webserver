package main

import (
	"fmt"
	"net/http"
	"sync"

	_ "github.com/mattn/go-sqlite3"

	"github.com/Loryhoof/webserver/db"
	"github.com/Loryhoof/webserver/handlers"
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

	http.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		handlers.WebsocketHandler(w, r, clients, &messages, &clientsMu, &messagesMu)
	})

	http.HandleFunc("/login", handlers.LoginHandler)
	http.HandleFunc("/register", handlers.RegisterHandler)
	http.HandleFunc("/verify-token", handlers.VerifyTokenHandler)
	http.HandleFunc("/refresh-token", handlers.RefreshTokenHandler)
	http.HandleFunc("/change-nickname", handlers.ChangeNicknameHandler)
	http.ListenAndServe(`:8080`, nil)
}
