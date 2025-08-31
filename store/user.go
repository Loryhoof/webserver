// user.go

package store

import (
	"github.com/Loryhoof/webserver/db"
)

func CreateUser(email string, pwHash string) error {
	database := db.GetDB()

	_, err := database.Exec(`INSERT INTO users (email, password_hash) VALUES (?, ?)`, email, pwHash)

	return err
}

func GetUserCredentialsByEmail(email string) (int, string, error) {
	database := db.GetDB()

	row := database.QueryRow(`SELECT id, password_hash FROM users WHERE email = ?`, email)

	var id int 
	var passwordHash string

	err := row.Scan(&id, &passwordHash)

	return id, passwordHash, err
}

func GetUserEmailById(id int) (string, error) {
	database := db.GetDB()

	row := database.QueryRow(`SELECT email FROM users WHERE id = ?`, id)

	var email string

	err := row.Scan(&email)

	return email, err
}

func UpdateUserNickname(nickname string, email string) error {
	database := db.GetDB()

	_, err := database.Exec(`UPDATE users SET nickname = ? WHERE email = ?`, nickname, email)

	return err
}