package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

var world World = World{}

func createPlayer(name string) Player {
	player := Player{name, 100, Vector3{0, 10, 0}, Quaternion{0, 0, 0, 1}}

	return player
}

func addPlayer(w http.ResponseWriter, req *http.Request) {
	type AddPlayerRequest struct {
		Name string `json:"name"`
		Position Vector3 `json:"position"`
	}

	var u AddPlayerRequest

	err := json.NewDecoder(req.Body).Decode(&u)

	if err != nil {
		fmt.Println(err)
		w.WriteHeader(500)
	}

	newPlayer := createPlayer(u.Name)
	world.addPlayer(newPlayer)

	w.Header().Set("Content-Type", "application-json")

	type ResponseObject struct {
		Name string `json:"name"`
		Health float32 `json:"health"`
		Position Vector3 `json:"position"`
		Quaternion Quaternion `json:"quaternion"`
	}

	response := ResponseObject(newPlayer)

	fmt.Println(response)
	json.NewEncoder(w).Encode(response)
}

func main() {

	ticker := time.NewTicker(time.Second / HZ)
	//i := 0
	defer ticker.Stop()

	

	var player Player = createPlayer("Kevin")
	world.addPlayer(player)

	// for range ticker.C {
	// 	i++

	// 	world.update(float32(HZ) / 1000)

	// }

	// http.HandleFunc("/calculate", getCalc)

	http.HandleFunc("/addPlayer", addPlayer)

	err := http.ListenAndServe(":3333", nil)

	if err != nil {
		fmt.Println(err)
	}
}
