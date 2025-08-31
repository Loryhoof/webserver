package handlers

import (
	"encoding/json"
	"log"
	"net/http"
	"strings"

	"github.com/Loryhoof/webserver/auth"
	"github.com/Loryhoof/webserver/store"
	"github.com/Loryhoof/webserver/types"
)

func ChangeNicknameHandler(w http.ResponseWriter, r *http.Request) {
	
	authHeader := r.Header.Get("Authorization")
	token := strings.TrimPrefix(authHeader, "Bearer ")

	err := auth.VerifyJWT(token)

	if err != nil {
		types.WriteError(w, http.StatusUnauthorized, "Unauthorized")
		return
	}

	email, err := auth.ParseJWT(token)

	if err != nil {
		types.WriteError(w, http.StatusInternalServerError, "Something went wrong")
		return
	}

	type RequestData struct {
		Nickname string `json:"nickname"`
	}

	v := RequestData{}

	err = json.NewDecoder(r.Body).Decode(&v)

	if err != nil {
		types.WriteError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	// got nickname

	//validate nickname
	if len(strings.TrimSpace(v.Nickname)) == 0 {
		types.WriteError(w, http.StatusBadRequest, "Nickname cannot be empty")
		return
	}

	if len(v.Nickname) > 32 {
		types.WriteError(w, http.StatusBadRequest, "Nickname too long")
		return
	}

	err = store.UpdateUserNickname(v.Nickname, email)

	if err != nil {
		log.Println("Error when store.UpdateUserNickname", err.Error())
		types.WriteError(w, http.StatusInternalServerError, "Something went wrong")
		return
	}

	types.WriteSuccess(w, "success")
}

func GetUserInfo(w http.ResponseWriter, r *http.Request) {

	b := r.Header.Get("Authorization")

	tkn := strings.TrimPrefix(b, "Bearer ")

	if len(tkn) == 0 {
		types.WriteError(w, http.StatusBadRequest, "Missing token")
		return
	}

	err := auth.VerifyJWT(tkn)

	if err != nil {
		types.WriteError(w, http.StatusUnauthorized, "Invalid token")
		return
	}

	email, err := auth.ParseJWT(tkn)

	if err != nil {
		types.WriteError(w, http.StatusInternalServerError, "Something went wrong")
		return
	}

	user, err := store.GetUserByEmail(email)

	if err != nil {
		types.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}

	types.WriteJSON(w, http.StatusOK, user)
}