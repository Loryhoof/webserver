package store

import (
	"github.com/Loryhoof/webserver/db"
	"github.com/Loryhoof/webserver/models"
)

func AddRefreshToken(refreshToken models.RefreshToken) error {

	database := db.GetDB()

	_, err := database.Exec(`INSERT INTO refresh_tokens (user_id, token, expiry) VALUES (?, ?, ?)`, refreshToken.UserID, refreshToken.Token, refreshToken.Expiry)

	return err
}

func DeleteRefreshToken(tokenString string) error {

	database := db.GetDB()

	_, err := database.Exec(`DELETE FROM refresh_tokens WHERE token = ?`, tokenString)

	return err
}

func GetRefreshTokenUserAndExpiry(tokenString string) (int, int64, error) {
	database := db.GetDB()

	row := database.QueryRow(`SELECT user_id, expiry FROM refresh_tokens WHERE token = ?`, tokenString)

	var userID int
	var expiry int64

	err := row.Scan(&userID, &expiry)

	return userID, expiry, err
}