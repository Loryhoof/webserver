package store

import (
	"log"

	"github.com/Loryhoof/webserver/db"
	"github.com/Loryhoof/webserver/models"
	"github.com/google/uuid"
)

func CreateMessage(userId string, content string) error {
	database := db.GetDB()

	_, err := database.Exec(`INSERT INTO messages (id, user_id, content) VALUES (?, ?, ?)`, uuid.NewString(), userId, content)

	return err
}

func GetAllMessages() ([]models.Message, error) {
	database := db.GetDB()

	msgArray := []models.Message{}

	rows, err := database.Query(`SELECT id, content, user_id FROM messages ORDER BY created_at ASC`)

	if err != nil {
		log.Println("GetAllMessage Error: ", err)
		return msgArray, err
	}

	defer rows.Close()

	for rows.Next() {

		msg := models.Message{}

		err := rows.Scan(&msg.ID, &msg.Content, &msg.UserID)

		if err != nil {
			log.Println("GetAllMessage Error: ", err)
			return msgArray, err
		}
		
		msgArray = append(msgArray, msg)
	}

	if err := rows.Err(); err != nil {
		return msgArray, err
	}


	return msgArray, nil
}