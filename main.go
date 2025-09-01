package main

import (
	"fmt"
	"log"
	"net/http"

	"github.com/Loryhoof/webserver/db"
	"github.com/Loryhoof/webserver/handlers"
	"github.com/Loryhoof/webserver/hubs"
	"github.com/Loryhoof/webserver/middleware"

	_ "github.com/mattn/go-sqlite3"
)

func main() {
	db.Init("./chat.db")
	defer db.Close()

	// connectedClients := make(map[string]*models.Client)
	// messages, _ := store.GetAllMessages()
	// serverUsers, _ := store.GetAllUsers()

	hub, err := hubs.NewHub()

	if err != nil {
		log.Println("Something went wrong on hubs.NewHub()")
		return
	}

	hub.Run()

	fmt.Println("Server running on port 8080")

	mux := http.NewServeMux()

	mux.Handle("/ws", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlers.WebsocketHandler(w, r, hub)
	}))

	mux.Handle("/verify-token", http.HandlerFunc(handlers.VerifyTokenHandler))
	mux.Handle("/login", http.HandlerFunc(handlers.LoginHandler))
	mux.Handle("/logout", http.HandlerFunc(handlers.LogoutHandler))
	mux.Handle("/register", http.HandlerFunc(handlers.RegisterHandler))
	mux.Handle("/refresh-token", http.HandlerFunc(handlers.RefreshTokenHandler))

	mux.Handle("/change-nickname", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlers.ChangeNicknameHandler(w, r, hub)
	}))

	mux.Handle("/user-info", http.HandlerFunc(handlers.GetUserInfoHandler))
	mux.Handle("/update-user", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlers.UpdateUserHandler(w, r, hub)
	}))


	http.ListenAndServe(`:8080`, middleware.Cors(mux))
}
