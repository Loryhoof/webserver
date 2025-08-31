package models

type RefreshToken struct {
	UserID int    `json:"userID"`
	Token  string `json:"token"`
	Expiry int64  `json:"expiry"`
}