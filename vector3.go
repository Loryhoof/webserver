package main

type Vector3 struct {
	X float32
	Y float32
	Z float32
}

func (v *Vector3) Add(vec *Vector3) *Vector3 {
	v.X += vec.X
	v.Y += vec.Y
	v.Z += vec.Z
	return v
}

func (v *Vector3) Sub(vec *Vector3) *Vector3 {
	v.X -= vec.X
	v.Y -= vec.Y
	v.Z -= vec.Z
	return v
}

func (v *Vector3) MultiplyScalar(scalar float32) *Vector3 {
	v.X *= scalar
	v.Y *= scalar
	v.Z *= scalar
	return v
}
