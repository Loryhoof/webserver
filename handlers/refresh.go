package handlers

import (
	"encoding/json"
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

	v := Data{}

	err := json.NewDecoder(r.Body).Decode(&v)

	if err != nil {
		types.WriteError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	userID, expiry, err := store.GetRefreshTokenUserAndExpiry(v.RefreshToken)
	
	if err != nil {
		types.WriteError(w, http.StatusInternalServerError, "Something went wrong")
		return
	}
	

	valid := expiry > time.Now().Unix()

	if valid {
		email, err := store.GetUserEmailById(userID)

		if err != nil {
			types.WriteError(w, http.StatusInternalServerError, "Something went wrong")
			return
		}
		
		accessToken, err := auth.CreateJWT(email)

		if err != nil {
			types.WriteError(w, http.StatusInternalServerError, "Something went wrong")
			return
		}

		err = store.DeleteRefreshToken(v.RefreshToken)

		if err != nil {
			types.WriteError(w, http.StatusInternalServerError, "Something went wrong")
			return
		}

		refreshToken := models.RefreshToken{UserID: userID, Token: uuid.NewString(), Expiry: time.Now().Add(time.Hour * 24 * 7).Unix()}
		err = store.AddRefreshToken(refreshToken)

		if err != nil {
			types.WriteError(w, http.StatusInternalServerError, "Something went wrong")
			return
		}

		types.WriteJSON(w, http.StatusOK, types.TokenResponse{AccessToken: accessToken, RefreshToken: refreshToken.Token})
	} else {
		types.WriteError(w, http.StatusUnauthorized, "Refresh Token Expired")
	}
}