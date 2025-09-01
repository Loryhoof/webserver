package handlers

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/Loryhoof/webserver/auth"
	"github.com/Loryhoof/webserver/db"
	"github.com/Loryhoof/webserver/hubs"
	"github.com/Loryhoof/webserver/models"
	"github.com/Loryhoof/webserver/store"
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

func WebsocketHandler(w http.ResponseWriter, r *http.Request, hub *hubs.Hub) {

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

	userID, err := auth.ParseJWT(tkn)

	if err != nil {
		types.WriteError(w, http.StatusInternalServerError, "Something went wrong")
		return
	}
	row := database.QueryRow(`SELECT nickname, color FROM users WHERE id = ?`, userID)

	var nickname string
	var color string

	err = row.Scan(&nickname, &color)

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

	client := models.Client{ID: userID, Connection: conn, Nickname: nickname, Color: color, Send: make(chan types.SocketEnvelope, 256)}

	//clientsMu.Lock()
	hub.Register(&client)
	// clients[userId] = &client
	//clientsMu.Unlock()
	
	fmt.Printf("Client connected: %v", client.ID)

	conn.SetCloseHandler(func(code int, text string) error {
		fmt.Println("\nClient sent close frame:", userID, "Code:", code, "Text:", text)
		hub.Unregister(&client)
		return nil
	})

	type HistoryEvent struct {
		Messages []models.Message `json:"messages"`
		Users []models.User `json:"serverUsers"`
	}

	messages, _ := store.GetAllMessages()
	users, _ := store.GetAllUsers()

	h := types.SocketEnvelope{Event: "history", Data: HistoryEvent{Messages: messages, Users: users}}

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

		newMessage := models.Message{ID: uuid.NewString(), Content: e.Message, UserID: userID, CreatedAt: time.Now().Local().String()}

		err = store.CreateMessage(newMessage.UserID, newMessage.Content)

		if err != nil {
			log.Println("Could not create message in DB", err)
			types.WriteError(w, http.StatusInternalServerError, "Something went wrong")
			return
		}

		hub.AddMessage(newMessage)

		//messagesMu.Lock()
	//	*messages = append(*messages, newMessage)

		//hub.Broadcast(newMessage)
//		messagesMu.Unlock()

		//v := types.SocketEnvelope{Event: "message", Data: newMessage}

		// broadcast? maybe?
		//clientsMu.Lock()
		// for _, client := range clientSlice {
		// 	err := client.Connection.WriteJSON(v)

		// 	if err != nil {
		// 		fmt.Println("write error, removing client:", client.ID, err)
		// 		client.Connection.Close()

		// 		//clientsMu.Lock()
		// 		//delete(clients, client.ID)
		// 		//clientsMu.Unlock()
		// 	}
		// }
		//clientsMu.Unlock()
	}
}