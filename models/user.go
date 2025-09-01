package models

import (
	"github.com/Loryhoof/webserver/types"
	"github.com/gorilla/websocket"
)

type Client struct {
	ID         string `json:"id"`
	Nickname   string `json:"nickname"`
	Color      string `json:"color"`
	Connection *websocket.Conn `json:"-"`
	Send 	   chan types.SocketEnvelope `json:"-"`
}

type User struct {
	ID         string `json:"id"`
	Nickname   string `json:"nickname"`
	Color      string `json:"color"`
}