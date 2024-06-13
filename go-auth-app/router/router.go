package router

import (
	"github.com/gorilla/mux"
	"go-auth-app/handlers"
	"go-auth-app/middleware"
)

func InitializeRouter() *mux.Router {
	r := mux.NewRouter()
	r.HandleFunc("/signup", handlers.SignUp).Methods("POST")
	r.HandleFunc("/login", handlers.Login).Methods("POST")
	r.HandleFunc("/protected", middleware.AuthMiddleware(handlers.ProtectedEndpoint)).Methods("GET")
	return r
}
