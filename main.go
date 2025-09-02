package main

import (
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/Loryhoof/webserver/db"
	"github.com/Loryhoof/webserver/handlers"
	"github.com/Loryhoof/webserver/hubs"
	"github.com/Loryhoof/webserver/middleware"

	_ "github.com/mattn/go-sqlite3"
)

func main() {

	mode := os.Getenv("MODE")

	db.Init("./chat.db")
	defer db.Close()

	hub, err := hubs.NewHub()

	if err != nil {
		log.Println("Something went wrong on hubs.NewHub()")
		return
	}

	hub.Run()

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

	if mode == "PROD" {
		log.Fatal(http.ListenAndServeTLS(
			":443",
			"/etc/letsencrypt/live/chatapp.kevinklatt.de/fullchain.pem",
			"/etc/letsencrypt/live/chatapp.kevinklatt.de/privkey.pem",
			middleware.Cors(mux),
		))
	}

	fmt.Println("DEV Server running on port 8080")
	log.Fatal(http.ListenAndServe(`:8080`, middleware.Cors(mux)))
}
