package main

type World struct {
	players []Player
}

func (world *World) update(delta float32) {
	for i := range world.players {
		world.players[i].update(delta)
	}
}

func (world *World) addPlayer(player Player) {
	world.players = append(world.players, player)
}
