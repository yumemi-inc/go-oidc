package main

type User struct {
	ID       string `form:"id"`
	Password string `form:"password"`
}
