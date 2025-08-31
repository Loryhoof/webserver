package handlers

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/Loryhoof/webserver/auth"
	"github.com/Loryhoof/webserver/db"
	"github.com/Loryhoof/webserver/models"
	"github.com/Loryhoof/webserver/types"
	"github.com/google/uuid"
)

func RefreshTokenHandler(w http.ResponseWriter, r *http.Request) {
	type Data struct {
		RefreshToken string `json:"refreshToken"`
	}

	b, err := io.ReadAll(r.Body)

	if err != nil {
		fmt.Println(err)
		return
	}

	v := Data{}

	json.Unmarshal(b, &v)

	database := db.GetDB()

	var userID int
	var expiry int64

	row := database.QueryRow(`SELECT user_id, expiry FROM refresh_tokens WHERE token = ?`, v.RefreshToken)
	err = row.Scan(&userID, &expiry)

	if err == sql.ErrNoRows {
		fmt.Println(err)

		w.WriteHeader(401)
		json.NewEncoder(w).Encode(types.ErrorResponse{Error: "No refresh token found"})
		return
	}

	if err != nil {
		fmt.Println(err)
		return
	}

	valid := expiry > time.Now().Unix()

	if valid {
		var email string
		row := database.QueryRow(`SELECT email FROM users WHERE id = ?`, userID)
		err = row.Scan(&email)

		if err == sql.ErrNoRows {
			panic(err)
		}

		accessToken, err := auth.CreateJWT(email)

		if err != nil {
			panic(err)
		}

		database.Exec(`DELETE FROM refresh_tokens WHERE token = ?`, v.RefreshToken)

		refreshToken := models.RefreshToken{UserID: userID, Token: uuid.NewString(), Expiry: time.Now().Add(time.Hour * 24 * 7).Unix()}

		database.Exec(`INSERT INTO refresh_tokens (user_id, token, expiry) VALUES (?, ?, ?)`, refreshToken.UserID, refreshToken.Token, refreshToken.Expiry)

		w.WriteHeader(200)
		json.NewEncoder(w).Encode(types.TokenResponse{AccessToken: accessToken, RefreshToken: refreshToken.Token})
	} else {
		w.WriteHeader(401)
		json.NewEncoder(w).Encode(types.ErrorResponse{Error: "refresh token expired"})
	}
}