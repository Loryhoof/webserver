package models

type RefreshToken struct {
	UserID string    `json:"userID"`
	Token  string `json:"token"`
	Expiry int64  `json:"expiry"`
}