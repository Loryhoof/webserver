package models

type Message struct {
	ID      string `json:"id"`
	Content string `json:"content"`
	UserID  string `json:"userId"`
	CreatedAt string `json:"createdAt"`
}