package main

import (
	"go-auth-app/router"
	"log"
	"net/http"
)

func main() {
	r := router.InitializeRouter()
	log.Fatal(http.ListenAndServe(":8080", r))
}
