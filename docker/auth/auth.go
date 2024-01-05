// Practica 3	Seguridad en Redes 2023/24	Laura Toledo Gutierrez

package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go" //go get github.com/dgrijalva/jwt-go
	"github.com/gin-gonic/gin"    //go get github.com/gin-gonic/gin
	"github.com/google/uuid"
	//go get github.com/google/uuid
)

const (
	USERS_PATH      = "users/"
	SHADOW_FILE     = ".shadow"
	TIME_EXPIRATION = 5
	KEY_PEM         = "keys/auth-key.ssl.key"
	IP_HOST         = "10.0.2.3"
	PORT            = "5000"
	CERT            = "certs/auth-cert.ssl.crt"
	KEY             = "7ce0bf4f88489514ce006f3efe0867076fd1717346e76c1db4f9665d938ce858"
)

var TOKENS_DICT = make(map[string]string)

type Credentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type Signup struct{}
type Login struct{}
type Authorize struct{}

func verifyUser(username string) bool {
	for user := range TOKENS_DICT {
		if username == user {
			return true
		}
	}
	return false
}

func verifyToken(username, token string) bool {
	// Parse the token
	parsedToken, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		// Check the signing method
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Invalid signing method")
		}
		return []byte(KEY), nil
	})

	// Handle token parsing errors
	if err != nil {
		fmt.Println("Error:", err)
		return false
	}

	// Check if the token is valid
	if parsedToken.Valid {
		// Check token claims
		claims, ok := parsedToken.Claims.(jwt.MapClaims)
		if !ok {
			fmt.Println("Invalid token claims")
			return false
		}

		// Check if the username matches the token
		if claims["username"] == username {
			// Check token expiration
			expirationTimeUnix, ok := claims["exp"].(float64)
			if !ok {
				fmt.Println("Invalid expiration time")
				return false
			}

			expirationTime := time.Unix(int64(expirationTimeUnix), 0)
			if expirationTime.Before(time.Now()) {
				fmt.Println("Token expired")
				return false
			}

			return true
		}

		fmt.Println("Username does not match the token")
		return false
	}

	fmt.Println("Invalid token")
	return false
}

func checkDirectories() {
	// Comprobar si el directorio de usuarios existe
	if _, err := os.Stat(USERS_PATH); os.IsNotExist(err) {
		os.Mkdir(USERS_PATH, os.ModeDir)
	}

	// Comprobar si el archivo de sombra (shadow file) existe
	if _, err := os.Stat(".shadow"); os.IsNotExist(err) {
		os.Create(".shadow")
	}
}

func encryptPassword(salt, password string) string {
	combination := salt + password

	sha := sha256.New()
	sha.Write([]byte(combination))
	encrypted := sha.Sum(nil)

	return hex.EncodeToString(encrypted)
}

func generateAccessToken(username string) string {
	expirationTime := time.Now().Add(time.Duration(TIME_EXPIRATION) * time.Minute)
	claims := jwt.MapClaims{
		"username": username,
		"exp":      expirationTime.Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(KEY))
	if err != nil {
		log.Fatal(err)
	}
	return tokenString
}

func (s *Signup) checkUsername(username string) bool {

	//Open the shadow file for reading
	shadowFile, err := os.Open(SHADOW_FILE)
	if err != nil {
		return false
	}
	defer shadowFile.Close()

	// To read the contents of the shadow file line by line
	scanner := bufio.NewScanner(shadowFile)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.Split(line, ":")[0] == username {
			return true
		}
	}
	return false
}

func (s *Signup) registerUser(username string, password string) error {
	shadowFile, err := os.OpenFile(SHADOW_FILE, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer shadowFile.Close()

	salt := uuid.New().String()
	encryptedPassword := encryptPassword(salt, password)
	credentials := fmt.Sprintf("%s:%s:%s\n", username, salt, encryptedPassword)

	if _, err := shadowFile.WriteString(credentials); err != nil {
		return err
	}
	return nil
}

func (s *Signup) post(c *gin.Context) {
	// Parse JSON input from the request body
	var jsonInput map[string]string
	if err := c.BindJSON(&jsonInput); err != nil {
		c.JSON(400, gin.H{"error": "Wrong format of the file"})
		return
	}

	username, existsU := jsonInput["username"]
	password, existPs := jsonInput["password"]
	if !existPs || !existsU {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Arguments must be 'username' and 'password'"})
		return
	}

	// Check if the username already exists
	if s.checkUsername(username) {
		c.JSON(409, gin.H{"error": fmt.Sprintf("Error, username %s already exists, try to login", username)})
		return
	}

	err := s.registerUser(username, password)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to register user"})
		return
	}

	token := generateAccessToken(username)
	TOKENS_DICT[username] = token

	c.JSON(200, gin.H{"access_token": token})

}

func (l *Login) checkCredentials(username, password string) bool {
	shadowFile, err := ioutil.ReadFile(".shadow")
	if err != nil {
		fmt.Printf("Error reading shadow file: %v\n", err)
		return false
	}

	lines := strings.Split(string(shadowFile), "\n")
	for _, line := range lines {
		credentials := strings.Split(line, ":")
		if len(credentials) != 3 {
			fmt.Println("Skipping malformed line in shadow file")
			continue
		}
		hashedPassword := encryptPassword(credentials[1], password)
		if credentials[0] == username && credentials[2] == hashedPassword {
			fmt.Println("Credentials verified successfully")
			return true
		}
	}

	fmt.Println("Credentials verification failed")
	return false
}

// LOGIN -> Hadle user post
func (l *Login) post(c *gin.Context) {
	// Parse JSON input from the request body
	var jsonInput map[string]string

	if err := c.BindJSON(&jsonInput); err != nil {
		c.JSON(400, gin.H{"error": "Wrong format of the file"})
		return
	}

	username, existU := jsonInput["username"]
	password, existP := jsonInput["password"]

	if !existP || !existU {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Username and password are required"})
		return
	}

	// Check user credentials
	if l.checkCredentials(username, password) {
		// Check if the user has a token associated, if not, generate one
		token, exists := TOKENS_DICT[username]
		if !exists {
			token = generateAccessToken(username)
			TOKENS_DICT[username] = token
			c.JSON(200, gin.H{"access_token": token})
			return
		}

		// If the user has a token, check its expiration date
		if verifyToken(username, token) {
			c.JSON(http.StatusOK, gin.H{"access_token": TOKENS_DICT[username]})
		} else {
			delete(TOKENS_DICT, username)
			token = generateAccessToken(username)
			TOKENS_DICT[username] = token
			c.JSON(http.StatusOK, gin.H{"access_token": token})
		}
	} else {
		c.JSON(401, gin.H{"error": "Error, user or password incorrect"})
	}
}

func (a *Authorize) authorize(c *gin.Context) {
	username := c.Query("username")
	token := c.Query("token")

	if verifyUser(username) {

		if verifyToken(username, token) {
			c.JSON(200, gin.H{})
		} else {
			c.JSON(400, gin.H{"error": "Wrong token"})
		}
		c.JSON(400, gin.H{"error": "User not found"})
	}
}

// MAIN
func main() {

	fmt.Println("Practica 4 - Laura Toledo Gutierrez")

	checkDirectories()
	// Define instances
	singup := Signup{}
	login := Login{}
	auth := Authorize{}

	// Set up gin router
	router := gin.Default()

	// Define Endpoints
	router.POST("/login", login.post)
	router.GET("/checking", auth.authorize)
	router.POST("/signup", singup.post)

	// Run gin server
	address := fmt.Sprintf("%s:%s", IP_HOST, PORT)
	router.RunTLS(address, CERT, KEY_PEM)
}
