package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync"

	"github.com/Loryhoof/webserver/auth"
	"github.com/Loryhoof/webserver/db"
	"github.com/Loryhoof/webserver/models"
	"github.com/Loryhoof/webserver/types"
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

func WebsocketHandler(w http.ResponseWriter, r *http.Request, clients map[string]*models.Client, messages *[]models.Message, clientsMu *sync.Mutex, messagesMu *sync.Mutex) {

	tkn := r.URL.Query().Get("token")

	if tkn == "" {
		types.WriteError(w, http.StatusBadRequest, "No token")
		return
	}

	err := auth.VerifyJWT(tkn)

	if err != nil {
		types.WriteError(w, http.StatusUnauthorized, "Invalid token")
		return
	}

	database := db.GetDB()

	email, err := auth.ParseJWT(tkn)

	if err != nil {
		types.WriteError(w, http.StatusInternalServerError, "Something went wrong")
		return
	}
	row := database.QueryRow(`SELECT id, nickname, color FROM users WHERE email = ?`, email)

	var userId string
	var nickname string
	var color string

	err = row.Scan(&userId, &nickname, &color)

	if err != nil {
		types.WriteError(w, http.StatusInternalServerError, "Something went wrong")
		return
	}

	fmt.Println(nickname, color)

	conn, err := upgrader.Upgrade(w, r, nil)

	if err != nil {
		fmt.Println(err)
		types.WriteError(w, http.StatusInternalServerError, "Something went wrong")
		return
	}

	// past this point we're connected

	client := models.Client{ID: userId, Connection: conn, Nickname: nickname, Color: color}

	clientsMu.Lock()
	clients[userId] = &client
	clientsMu.Unlock()
	
	fmt.Printf("Client connected: %v", client.ID)

	conn.SetCloseHandler(func(code int, text string) error {
		fmt.Println("\nClient sent close frame:", userId, "Code:", code, "Text:", text)
		
		clientsMu.Lock()
		delete(clients, userId)
		clientsMu.Unlock()

		return nil
	})

	type HistoryEvent struct {
		Users []*models.Client `json:"users"`
		Messages []models.Message `json:"messages"`
	}
	
	clientSlice := make([]*models.Client, 0, len(clients))
	for _, c := range clients {
		clientSlice = append(clientSlice, c)
	}

	h := types.SocketEnvelope{Event: "history", Data: HistoryEvent{Messages: *messages, Users: clientSlice}}

	conn.WriteJSON(h)

	defer conn.Close()

	for {
		_, b, err := conn.ReadMessage()

		if err != nil {
			fmt.Println("Error on reading message")
			types.WriteError(w, http.StatusInternalServerError, "Something went wrong")
			return
		}

		type IncomingMessage struct {
			Event   string `json:"event"`
			Message string `json:"message"`
		}

		var e IncomingMessage

		json.Unmarshal(b, &e)

		newMessage := models.Message{ID: uuid.NewString(), Content: e.Message, UserID: userId}

		messagesMu.Lock()
		*messages = append(*messages, newMessage)
		messagesMu.Unlock()

		v := types.SocketEnvelope{Event: "message", Data: newMessage}

		// broadcast? maybe?
		clientsMu.Lock()
		for _, client := range clients {
			err := client.Connection.WriteJSON(v)

			if err != nil {
				fmt.Println("write error, removing client:", client.ID, err)
				client.Connection.Close()

				clientsMu.Lock()
				delete(clients, client.ID)
				clientsMu.Unlock()
			}
		}
		clientsMu.Unlock()
	}
}