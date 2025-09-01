// user.go

package store

import (
	"log"

	"github.com/Loryhoof/webserver/db"
	"github.com/Loryhoof/webserver/models"
	"github.com/google/uuid"
)

type User struct {
		ID string `json:"id"`
		Email string `json:"email"`
		Nickname string `json:"nickname"`
		Color string `json:"color"`
		CreatedAt string `json:"createdAt"`
	}

func CreateUser(email string, pwHash string) error {
	database := db.GetDB()

	_, err := database.Exec(`INSERT INTO users (id, email, password_hash) VALUES (?, ?, ?)`, uuid.NewString(), email, pwHash)

	return err
}

func GetAllUsers() ([]models.User, error) {
	users := []models.User{}

	database := db.GetDB()

	rows, err := database.Query(`SELECT id, nickname, color FROM users`)

	if err != nil {
		log.Println("Error in GetAllUsers: ", err)
		return users, err
	}
	
	for rows.Next() {
		user := models.User{}

		err = rows.Scan(&user.ID, &user.Nickname, &user.Color)

		if err != nil {
			log.Println("Error in GetAllUsers for rows.Next() {} ", err)
			return users, err
		}

		users = append(users, user)
	}

	if err := rows.Err(); err != nil {
		log.Println("GetAllUsers rows.Err(), ", err)
		return users, err
	}

	return users, nil
}

func GetUserCredentialsByEmail(email string) (string, string, error) {
	database := db.GetDB()

	row := database.QueryRow(`SELECT id, password_hash FROM users WHERE email = ?`, email)

	var id string 
	var passwordHash string

	err := row.Scan(&id, &passwordHash)

	return id, passwordHash, err
}

func GetUserEmailById(id string) (string, error) {
	database := db.GetDB()

	row := database.QueryRow(`SELECT email FROM users WHERE id = ?`, id)

	var email string

	err := row.Scan(&email)

	return email, err
}

func UpdateUserNickname(nickname string, userID string) error {
	database := db.GetDB()

	_, err := database.Exec(`UPDATE users SET nickname = ? WHERE id = ?`, nickname, userID)

	return err
}

func UpdaterUserColor(color string, userID string) error {
	database := db.GetDB()

	_, err := database.Exec(`UPDATE users SET color = ? WHERE id = ?`, color, userID)

	return err
}

func GetUser(userID string) (User, error) {
	database := db.GetDB()

	row := database.QueryRow(`SELECT id, email, nickname, color, created_at FROM users WHERE id = ?`, userID)

	u := User{}

	err := row.Scan(&u.ID, &u.Email, &u.Nickname, &u.Color, &u.CreatedAt)

	if err != nil {
		return u, err
	}

	return u, nil
}