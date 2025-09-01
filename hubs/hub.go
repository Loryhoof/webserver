package hubs

import (
	"fmt"

	"github.com/Loryhoof/webserver/models"
	"github.com/Loryhoof/webserver/types"
)

type Hub struct {
	connectedClients map[string]*models.Client
	messages []models.Message
	register chan *models.Client
	unregister chan *models.Client
	broadcast chan types.SocketEnvelope
	getClients chan chan []models.Client
	getMessages chan chan []models.Message
	addMessage chan models.Message

	updateUser chan models.Client
}

func NewHub() (*Hub, error) {
	hub := Hub{
		connectedClients: make(map[string]*models.Client),
		messages: []models.Message{},
		register: make(chan *models.Client),
		unregister: make(chan *models.Client),
		broadcast: make(chan types.SocketEnvelope),
		getClients: make(chan chan []models.Client),
		getMessages: make(chan chan []models.Message),
		addMessage: make(chan models.Message),

		updateUser: make(chan models.Client),
	}
	return &hub, nil
}

func hubLoop(hub *Hub) {
	
	for {
		select {
		case msg := <-hub.broadcast:

			fmt.Println(msg)
		
		case client := <-hub.register:

			hub.connectedClients[client.ID] = client

			// broadcast (all except self)
			for _, c := range hub.connectedClients {

				if(c.ID == client.ID) {
					continue
				}
				payload := types.SocketEnvelope{Event: "user_joined", Data: client}
				c.Send <- payload
			}

			go func(c *models.Client) {
				for msg := range c.Send {
					if err := c.Connection.WriteJSON(msg); err != nil {
						break
					}
				}
			}(client)

		case client := <-hub.unregister:

			// broadcast (all except self)
			for _, c := range hub.connectedClients {
				if c.ID == client.ID {
					continue
				}

				payload := types.SocketEnvelope{Event: "user_left", Data: client}
				c.Send <- payload
			}

			delete(hub.connectedClients, client.ID)
			close(client.Send)

		case replyChan := <-hub.getClients:

			copyArr := []models.Client{}
			for _, val := range hub.connectedClients {
				copy := models.Client{ID: val.ID, Nickname: val.Nickname, Color: val.Color, Connection: val.Connection}
				copyArr = append(copyArr, copy)
			}
			
			replyChan <- copyArr

		case replyChan := <-hub.getMessages:
			replyChan <- hub.messages

		case msg := <-hub.addMessage:

			hub.messages = append(hub.messages, msg)
			
			// broacast msg
			for _, client := range hub.connectedClients {
				payload := types.SocketEnvelope{Event: "message", Data: msg}

				client.Send <- payload
			}

		case updated := <-hub.updateUser:

			c, exists := hub.connectedClients[updated.ID]

			if exists {
				c.Nickname = updated.Nickname
				c.Color = updated.Color
			}


			// broadcast updated profile
			for _, client := range hub.connectedClients {
				payload := types.SocketEnvelope{Event: "update_user", Data: c}
				client.Send <- payload
			}

		}
	}
}


func (hub *Hub) Run() {
	go hubLoop(hub)
}

func (hub *Hub) Register(client *models.Client) {
	hub.register <- client
}

func (hub *Hub) Unregister(client *models.Client) {
	hub.unregister <- client
}

func (hub *Hub) Broadcast(msg types.SocketEnvelope) {
	hub.broadcast <- msg
}

func (hub *Hub) GetClients() []models.Client {

	replyChan := make(chan []models.Client)
	hub.getClients <- replyChan
	return <-replyChan
}

func (hub *Hub) GetMessages() []models.Message {

	replyChan := make(chan []models.Message)
	hub.getMessages <- replyChan
	return <-replyChan
}

func (hub *Hub) AddMessage(message models.Message) {
	hub.addMessage <- message
}

func (hub *Hub) UpdateUser(updated models.Client) {
	hub.updateUser <- updated
}
