package handlers

import (
	"encoding/json"
	"go-auth-app/models"
	"go-auth-app/utils"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"net/http"
	"regexp"
)

type Credentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Email    string `json:"email"`
}

var db *gorm.DB

func init() {
	var err error
	db, err = gorm.Open(sqlite.Open("users.db"), &gorm.Config{})
	if err != nil {
		panic("failed to connect database")
	}
	db.AutoMigrate(&models.User{})
}

func isValidEmail(email string) bool {
	regex := regexp.MustCompile(`^[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,4}$`)
	return regex.MatchString(email)
}

func SignUp(w http.ResponseWriter, r *http.Request) {
	var creds Credentials
	err := json.NewDecoder(r.Body).Decode(&creds)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	if len(creds.Username) < 4 || len(creds.Password) < 8 || !isValidEmail(creds.Email) {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	hashedPassword, err := utils.HashPassword(creds.Password)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	user := models.User{Username: creds.Username, Password: hashedPassword, Email: creds.Email}
	result := db.Create(&user)
	if result.Error != nil {
		w.WriteHeader(http.StatusConflict)
		return
	}

	w.WriteHeader(http.StatusCreated)
}

func Login(w http.ResponseWriter, r *http.Request) {
	var creds Credentials
	err := json.NewDecoder(r.Body).Decode(&creds)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	if len(creds.Username) < 4 || len(creds.Password) < 8 {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	var user models.User
	result := db.Where("username = ?", creds.Username).First(&user)
	if result.Error != nil {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	if !utils.CheckPasswordHash(creds.Password, user.Password) {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	tokenString, err := utils.GenerateJWT(creds.Username)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.Write([]byte(tokenString))
}

func ProtectedEndpoint(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("This is a protected endpoint"))
}
