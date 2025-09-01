package handlers

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/Loryhoof/webserver/auth"
	"github.com/Loryhoof/webserver/hubs"
	"github.com/Loryhoof/webserver/models"
	"github.com/Loryhoof/webserver/store"
	"github.com/Loryhoof/webserver/types"
)

func UpdateUserHandler(w http.ResponseWriter, r *http.Request, hub *hubs.Hub) {

	authHeader := r.Header.Get("Authorization")
	token := strings.TrimPrefix(authHeader, "Bearer ")

	if len(token) == 0 {
		types.WriteError(w, http.StatusBadRequest, "No token")
		return
	}

	err := auth.VerifyJWT(token)

	if err != nil {
		types.WriteError(w, http.StatusUnauthorized, "Unauthorized")
		return
	}

	userID, err := auth.ParseJWT(token)

	if err != nil {
		types.WriteError(w, http.StatusInternalServerError, "Something went wrong")
		return
	}

	type RequestData struct {
		Field string `json:"field"`
		Value string `json:"value"`
	}

	v := RequestData{}

	json.NewDecoder(r.Body).Decode(&v)

	if (v.Field == "color") {
		err := store.UpdaterUserColor(v.Value, userID)

		if err != nil {
			types.WriteError(w, http.StatusInternalServerError, "Something went wrong")
			return
		}
	}

	user, err := store.GetUser(userID)

	if err != nil {
		types.WriteError(w, http.StatusInternalServerError, "Something went wrong")
		return
	}

	hub.UpdateUser(models.Client{ID: user.ID, Nickname: user.Nickname, Color: user.Color})

	types.WriteSuccess(w, "success")
}

func ChangeNicknameHandler(w http.ResponseWriter, r *http.Request, hub *hubs.Hub) {
	
	authHeader := r.Header.Get("Authorization")
	token := strings.TrimPrefix(authHeader, "Bearer ")

	err := auth.VerifyJWT(token)

	if err != nil {
		types.WriteError(w, http.StatusUnauthorized, "Unauthorized")
		return
	}

	userID, err := auth.ParseJWT(token)

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

	//hub.Broadcast(models.Message{ID: "", Content: "sex man", UserID: "Sexy"})

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


	err = store.UpdateUserNickname(v.Nickname, userID)


	if err != nil {
		log.Println("Error when store.UpdateUserNickname", err.Error())
		types.WriteError(w, http.StatusInternalServerError, "Something went wrong")
		return
	}

	newUser, err := store.GetUser(userID)

	if err != nil {
		log.Println("Error when store.GetUser()", err.Error())
		types.WriteError(w, http.StatusInternalServerError, "Something went wrong")
		return
	}
	
	hub.UpdateUser(models.Client{ID: newUser.ID, Nickname: newUser.Nickname, Color: newUser.Color})

	types.WriteSuccess(w, "success")
}

func GetUserInfoHandler(w http.ResponseWriter, r *http.Request) {

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

	userID, err := auth.ParseJWT(tkn)
	fmt.Println(userID, "USER IT GETUSERINFOHANDLER")

	if err != nil {
		types.WriteError(w, http.StatusInternalServerError, "Something went wrong")
		return
	}

	user, err := store.GetUser(userID)

	if err != nil {
		types.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}

	types.WriteJSON(w, http.StatusOK, user)
}