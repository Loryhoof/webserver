// player.go

package main

import "fmt"

type Player struct {
	Name       string
	Health     float32
	Position   Vector3
	Quaternion Quaternion
}

func (e *Player) update(delta float32) {

	e.Position.Y -= GRAVITY * delta

	// Floor
	if e.Position.Y <= 0 {
		e.Position.Y = 0
	}

	const SPEED float32 = 5.0

	var dirVec Vector3 = Vector3{0, 0, SPEED}

	e.Position.Add(dirVec.MultiplyScalar(delta))

	fmt.Printf("\n%v at Y: %v", e.Name, e.Position)

}
