package main

import (
	"encoding/json"
	"fmt"
	"net/http"

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

var clients = make(map[string]Client)

type Message struct {
	ID      string `json:"id"`
	Message string `json:"message"`
}

var messages []Message

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
			Type string `json:"type"`
			ID      string `json:"id"`
			Message string `json:"message"`
		}

		fmt.Println(string(b))
		v := OutgoingMessage{Type: "message", ID: id, Message: e.Message}

		//conn.WriteJSON(v)

		// broadcast? maybe? 
		for _, client := range clients {
			err := client.Connection.WriteJSON(v)

			if(err != nil) {
				fmt.Println("write error, removing client:", client.ID, err)
				client.Connection.Close()
				delete(clients, client.ID)
			}
			
		}
	}
}

func main() {

	fmt.Println("Server running on port 8080")

	http.HandleFunc("/ws", wsHandler)
	http.ListenAndServe(`:8080`, nil)
}
