package handlers

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/Loryhoof/webserver/auth"
	"github.com/Loryhoof/webserver/models"
	"github.com/Loryhoof/webserver/store"
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

	userID, expiry, err := store.GetRefreshTokenUserAndExpiry(v.RefreshToken)
	

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
		email, err := store.GetUserEmailById(userID)

		if err != nil {
			panic(err)
		}
		
		accessToken, err := auth.CreateJWT(email)

		if err != nil {
			panic(err)
		}

		err = store.DeleteRefreshToken(v.RefreshToken)

		if err != nil {
			panic(err)
		}

		refreshToken := models.RefreshToken{UserID: userID, Token: uuid.NewString(), Expiry: time.Now().Add(time.Hour * 24 * 7).Unix()}
		err = store.AddRefreshToken(refreshToken)

		if err != nil {
			panic(err)
		}


		w.WriteHeader(200)
		json.NewEncoder(w).Encode(types.TokenResponse{AccessToken: accessToken, RefreshToken: refreshToken.Token})
	} else {
		w.WriteHeader(401)
		json.NewEncoder(w).Encode(types.ErrorResponse{Error: "refresh token expired"})
	}
}