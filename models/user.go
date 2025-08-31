package models

import "github.com/gorilla/websocket"

type Client struct {
	ID         string `json:"id"`
	Nickname   string `json:"nickname"`
	Color      string `json:"color"`
	Connection *websocket.Conn `json:"-"`
}