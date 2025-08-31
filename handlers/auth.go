package handlers

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/Loryhoof/webserver/auth"
	"github.com/Loryhoof/webserver/models"
	"github.com/Loryhoof/webserver/store"
	"github.com/Loryhoof/webserver/types"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

func RegisterHandler(w http.ResponseWriter, r *http.Request) {
	type Data struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	v := Data{}

	err := json.NewDecoder(r.Body).Decode(&v)

	if err != nil {
		types.WriteError(w, http.StatusBadRequest, "Invalid form body")
		return
	}

	pwd, err := bcrypt.GenerateFromPassword([]byte(v.Password), bcrypt.DefaultCost)

	if err != nil {
		types.WriteError(w, http.StatusInternalServerError, "Something went wrong")
		return
	}

	// normalize email
	v.Email = strings.TrimSpace(strings.ToLower(v.Email))

	err = store.CreateUser(v.Email, string(pwd))

	if err != nil {
		if(strings.Contains(err.Error(), "UNIQUE constraint failed")) {
			types.WriteError(w, http.StatusConflict, "User already exists")
			return
		}

		types.WriteError(w, http.StatusInternalServerError, "Something went wrong")
		return
	}

	types.WriteSuccess(w, "success")
}

func LoginHandler(w http.ResponseWriter, r *http.Request) {

	type Data struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	v := Data{}

	err := json.NewDecoder(r.Body).Decode(&v)

	if err != nil {
		types.WriteError(w, http.StatusBadRequest, "Invalid form body")
		return
	}

	// normalize email
	v.Email = strings.TrimSpace(strings.ToLower(v.Email))

	userID, passwordHash, err := store.GetUserCredentialsByEmail(v.Email)

	if err != nil {
		types.WriteError(w, http.StatusUnauthorized, "Invalid credentials")
		return
	}

	err = bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(v.Password))

	if err != nil {
		types.WriteError(w, http.StatusUnauthorized, "Invalid credentials")
		return
	}

	accTkn, err := auth.CreateJWT(v.Email)

	if err != nil {
		types.WriteError(w, http.StatusInternalServerError, "Something went wrong")
		return
	}

	expiry := time.Now().Add(time.Hour * 24 * 7).UTC().Unix() // 7 days
	refTkn := models.RefreshToken{UserID: userID, Token: uuid.NewString(), Expiry: expiry}

	err = store.AddRefreshToken(refTkn)

	if err != nil {
		types.WriteError(w, http.StatusInternalServerError, "Something went wrong")
		return
	}

	types.WriteJSON(w, http.StatusOK, types.TokenResponse{AccessToken: accTkn, RefreshToken: refTkn.Token})
}

func LogoutHandler(w http.ResponseWriter, r *http.Request) {
	b := r.Header.Get("Authorization")
	tkn := strings.TrimPrefix(b, "Bearer ")

	type Req struct {
		RefreshToken string `json:"refreshToken"`
	}

	v := Req{}

	json.NewDecoder(r.Body).Decode(&v)

	if len(tkn) == 0 {
		types.WriteError(w, http.StatusBadRequest, "No token provided")
		return
	}
	err := store.DeleteRefreshToken(v.RefreshToken)

	if err != nil {
		types.WriteError(w, http.StatusInternalServerError, "Something went wrong when deleting Refresh Token")
		return
	}

	types.WriteSuccess(w, "success")
}