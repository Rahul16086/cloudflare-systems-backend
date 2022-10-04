package main

import (
	"encoding/json"
	"fmt"
	"github.com/golang-jwt/jwt"
	"github.com/gorilla/mux"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"time"
)

var mySign = []byte("secret")

type Users struct {
	Users []User `json:"users"`
}

type User struct {
	Username string `json:"name"`
	Auth     int    `json:"auth"`
	Verify   int    `json:"verify"`
}

var currUser string
var present bool

func userAuth(writer http.ResponseWriter, req *http.Request) {
	privateKey, err := ioutil.ReadFile("id_rsa")
	if err != nil {
		log.Println(err)
	}

	if err != nil {
		log.Println(err)
	}
	ptkey, err := jwt.ParseRSAPrivateKeyFromPEM(privateKey)
	if err != nil {
		log.Println(err)
	}
	publicKey, err := ioutil.ReadFile("id_rsa.pub")
	if err != nil {
		log.Println(err)
	}
	token := jwt.New(jwt.GetSigningMethod("RS256"))
	if err != nil {
		log.Println(err)
	}
	claims := token.Claims.(jwt.MapClaims)
	params := mux.Vars(req)
	expirationTime := time.Now().Add(time.Hour * 24)
	writer.Header().Set("Access-Control-Allow-Origin", "*")
	writer.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
	writer.Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Content-Length, "+
		"Accept-Encoding, X-CSRF-Token, Authorization")
	for _, param := range params {
		currUser = param
	}
	claims["sub"] = currUser
	claims["authorized"] = true
	claims["exp"] = expirationTime.Unix()

	tokenString, err := token.SignedString(ptkey)
	if err != nil {
		fmt.Fprintf(writer, err.Error())
	}
	http.SetCookie(writer, &http.Cookie{
		Name:     "token",
		Value:    tokenString,
		Expires:  expirationTime,
		Path:     "/",
		HttpOnly: true,
	})
	writer.Header().Set("Content-Type", "Text/Html")
	writer.Write(publicKey)

	statData, err := os.Open("data.json")
	if err != nil {
		fmt.Fprintf(writer, err.Error())
	}

	byteVal, _ := ioutil.ReadAll(statData)

	var users Users
	var updatedUser Users
	json.Unmarshal(byteVal, &users)
	for _, user := range users.Users {
		if user.Username == currUser {
			present = true
			user.Auth = user.Auth + 1
		}
		updatedUser.Users = append(updatedUser.Users, user)
	}
	jsonUpdated, err := json.Marshal(updatedUser)
	if err != nil {
		log.Println(err)
		return
	}
	writeErr := ioutil.WriteFile("data.json", jsonUpdated, 0644)
	if writeErr != nil {
		log.Println(writeErr)
		return
	}

	if !present {
		var newUser User
		newUser.Username = currUser
		newUser.Auth = 1
		newUser.Verify = 0
		final := append(users.Users, newUser)
		var newKeyValue Users
		finalKv := append(newKeyValue.Users, final...)
		newKeyValue.Users = finalKv
		jsonUpdated, err := json.Marshal(newKeyValue)
		if err != nil {
			log.Println(err)
			return
		}
		writeErr := ioutil.WriteFile("data.json", jsonUpdated, 0644)
		if writeErr != nil {
			log.Println(writeErr)
			return
		}
	}

}

func verify(writer http.ResponseWriter, req *http.Request) {
	writer.Header().Set("Access-Control-Allow-Origin", "*")
	writer.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
	writer.Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Content-Length, "+
		"Accept-Encoding, X-CSRF-Token, Authorization")
	publicKey, err := ioutil.ReadFile("id_rsa.pub")
	if err != nil {
		log.Println(err)
	}
	pbKey, err := jwt.ParseRSAPublicKeyFromPEM(publicKey)
	if err != nil {
		log.Println(err)
	}
	cookie, err := req.Cookie("token")
	if err != nil {
		if err == http.ErrNoCookie {
			writer.WriteHeader(400)
			fmt.Fprintf(writer, "No cookie found")
		}
		writer.WriteHeader(400)
		fmt.Fprintf(writer, err.Error())
		return
	}
	tokenString := cookie.Value
	parsedToken, err := jwt.Parse(tokenString,
		func(token *jwt.Token) (interface{}, error) {
			return pbKey, nil
		})
	if err != nil {
		if err == jwt.ErrSignatureInvalid {
			writer.WriteHeader(http.StatusUnauthorized)
			fmt.Fprintf(writer, "Unauthorized")
		}
		writer.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(writer, err.Error())
	}
	if !parsedToken.Valid {
		writer.WriteHeader(http.StatusUnauthorized)
		fmt.Fprintf(writer, "Invalid token")
	} else {
		parsedClaims := parsedToken.Claims.(jwt.MapClaims)
		writer.Header().Set("Content-Type", "Text/Html")
		writer.Write([]byte(parsedClaims["sub"].(string)))
		statData, err := os.Open("data.json")
		if err != nil {
			fmt.Fprintf(writer, err.Error())
		}

		byteVal, _ := ioutil.ReadAll(statData)
		var users Users
		var updatedUser Users
		json.Unmarshal(byteVal, &users)
		for _, user := range users.Users {
			if user.Username == currUser {
				present = true
				user.Verify = user.Verify + 1
			}
			updatedUser.Users = append(updatedUser.Users, user)
		}
		jsonUpdated, err := json.Marshal(updatedUser)
		if err != nil {
			log.Println(err)
			return
		}
		writeErr := ioutil.WriteFile("data.json", jsonUpdated, 0644)
		if writeErr != nil {
			log.Println(writeErr)
			return
		}
	}
}

func readMeFile(writer http.ResponseWriter, req *http.Request) {
	writer.Header().Set("Access-Control-Allow-Origin", "*")
	writer.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
	writer.Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Content-Length, "+
		"Accept-Encoding, X-CSRF-Token, Authorization")
	content, err := ioutil.ReadFile("README.txt")
	if err != nil {
		writer.WriteHeader(http.StatusBadRequest)
	}
	fmt.Fprintf(writer, string(content))
}

func loadStats(writer http.ResponseWriter, req *http.Request) {
	writer.Header().Set("Access-Control-Allow-Origin", "*")
	writer.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
	writer.Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Content-Length, "+
		"Accept-Encoding, X-CSRF-Token, Authorization")
	statData, err := os.Open("data.json")
	if err != nil {
		fmt.Fprintf(writer, err.Error())
	}

	byteVal, _ := ioutil.ReadAll(statData)

	var users Users
	json.Unmarshal(byteVal, &users)
	for _, user := range users.Users {
		fmt.Fprintf(writer,
			"{Username: %s, Auth: %d, Verify: %d, Average: %d}\n\n", user.Username, user.Auth, user.Verify, (user.Auth+user.Verify)/2)
	}
}

func cors(writer http.ResponseWriter, req *http.Request) {
	writer.Header().Set("Access-Control-Allow-Origin", "*")
	writer.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
	writer.Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Content-Length, "+
		"Accept-Encoding, X-CSRF-Token, Authorization")
}

func main() {
	router := mux.NewRouter()
	router.HandleFunc("/auth/{username}", userAuth).Methods("GET")
	router.HandleFunc("/verify", verify).Methods("GET")
	router.HandleFunc("/README.txt", readMeFile).Methods("GET")
	router.HandleFunc("/stats", loadStats).Methods("GET")
	router.HandleFunc("*", cors).Methods("OPTIONS")
	http.ListenAndServe(":8080", router)
}
