// Practica 3	Seguridad en Redes 2023/24	Laura Toledo Gutierrez

package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
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
	KEY             = "b70a82b92875605defbeda92cfdabf0362aa4cac8e784b6445f2726a8a54abc0"
)

var TOKENS_DICT = make(map[string]string)

type Signup struct{}
type Login struct{}
type Authorize struct{}

func verifyUser(username string) bool {
	_, exists := TOKENS_DICT[username]
	return exists
}

func verifyToken(username, tokenString string) (bool, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header[""])
		}
		return KEY, nil
	})

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		if exp, ok := claims["exp"].(float64); ok {
			dateExpired := time.Unix(int64(exp), 0)
			if dateExpired.Before(time.Now()) {
				return false, fmt.Errorf("token expired")
			}
		}

		if claims["username"] != username {
			return false, fmt.Errorf("Username does not match the token")
		}
		return true, nil
	} else {
		return false, err
	}
}

func checkDirectories() error {
	if _, err := os.Stat(USERS_PATH); os.IsNotExist(err) {
		if err := os.Mkdir(USERS_PATH, 0755); err != nil {
			return err
		}
	}
	if _, err := os.Stat(".shadow"); os.IsNotExist(err) {
		file, err := os.Create(".shadow")
		if err != nil {
			return err
		}
		defer file.Close()
	}
	return nil
}

func encryptPassword(salt, password string) string {
	combination := salt + password

	sha := sha256.New()
	sha.Write([]byte(combination))
	encrypted := sha.Sum(nil)

	return hex.EncodeToString(encrypted)
}

func generateAccessToken(username string) (string, error) {
	token := jwt.New(jwt.SigningMethodHS256)

	claims := token.Claims.(jwt.MapClaims)
	claims["username"] = username
	claims["exp"] = time.Now().Add(time.Minute * TIME_EXPIRATION).Unix()

	tokenString, err := token.SignedString([]byte(KEY))
	if err != nil {
		return "", err
	}
	return tokenString, nil

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

func (s *Signup) registerUser(username, password string) error {
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

	// Extract username from the JSON input
	username, exists := jsonInput["username"]
	if !exists {
		c.JSON(400, gin.H{"error": "Arguments must be 'username' and 'password'"})
		return
	}
	// Extract password from the JSON input
	password, exists := jsonInput["password"]
	if !exists {
		c.JSON(400, gin.H{"error": "Arguments must be 'username' and 'password'"})
		return
	}

	// Check if the username already exists
	if s.checkUsername(username) {
		c.JSON(409, gin.H{"error": fmt.Sprintf("Error, username %s already exists, try to login", username)})
		return
	}

	if err := s.registerUser(username, password); err != nil {
		c.JSON(400, gin.H{"error": "Error registering user"})
	}

	token, err := generateAccessToken(username)
	if err != nil {
		c.JSON(400, gin.H{"error": "Error generating access token"})
	}

	TOKENS_DICT[username] = token

	c.JSON(200, gin.H{"access_token": token})

}

// LOGIN -> Check user credentials against a shadow file
func (l *Login) CheckCredentials(username, password string, c *gin.Context) bool {
	// Open shadow file
	shadowFile, err := os.Open(SHADOW_FILE)
	if err != nil {
		c.JSON(500, gin.H{"error": "Error opening shadow file"})
		return false
	}
	defer shadowFile.Close()
	// Read the contents of the file line by line
	scanner := bufio.NewScanner(shadowFile)
	for scanner.Scan() {
		line := scanner.Text()
		credentials := strings.Split(line, ":")

		if credentials[0] == username {
			// Encrypt the provided password with the stored salt from the shadow file
			hashedPassword := encryptPassword(credentials[1], password)
			if err != nil {
				c.JSON(500, gin.H{"error": "Error encrypting password"})
				return false
			}
			// Check if the hashed passsword matches the stored hashed password
			if strings.TrimSpace(credentials[2]) == hashedPassword {
				return true
			}
		}
	}
	return false
}

// LOGIN -> Hadle user login
func (l *Login) Login(c *gin.Context) {
	// Parse JSON input from the request body
	var jsonInput map[string]string

	if err := c.BindJSON(&jsonInput); err != nil {
		c.JSON(400, gin.H{"error": "Wrong format of the file"})
		return
	}

	// Extract username from the JSON input
	username, exists := jsonInput["username"]
	if !exists {
		c.JSON(400, gin.H{"error": "Arguments must be 'username' and 'password'"})
		return
	}

	// Extract password from the JSON input
	password, exists := jsonInput["password"]
	if !exists {
		c.JSON(400, gin.H{"error": "Arguments must be 'username' and 'password'"})
		return
	}

	// Check user credentials
	if l.CheckCredentials(username, password, c) {
		// Check if the user has a token associated, if not, generate one
		token, exists := TOKENS_DICT[username]
		if !exists {
			token, err := generateAccessToken(username)
			if err != nil {
				c.JSON(400, gin.H{"error": "Error generating access token"})
				return
			}
			TOKENS_DICT[username] = token
			c.JSON(200, gin.H{"access_token": token})
			return
		}

		// If the user has a token, check its expiration date
		valid, err := verifyToken(username, token)
		if err != nil || !valid {
			token, err := generateAccessToken(username)
			if err != nil {
				c.JSON(400, gin.H{"error": "Error generating access token"})
				return
			}
			TOKENS_DICT[username] = token
			c.JSON(200, gin.H{"access_token": token})
			return
		}
	} else {
		c.JSON(401, gin.H{"error": "Error, user or password incorrect"})
	}
}

func (a *Authorize) authorize(c *gin.Context) {
	username := c.Query("username")
	token := c.Query("token")

	if verifyUser(username) {

		valid, err := verifyToken(username, token)
		if err != nil {
			c.JSON(400, gin.H{"error": "Error verifying token"})
		}
		if valid {
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

	// Use the Middlware for all routes that requires authorization

	// Define Endpoints
	router.POST("/login", login.Login)
	router.GET("/authorize", auth.authorize)
	router.POST("/signup", singup.post)

	// Run gin server
	err := router.RunTLS("myserver.local:5000", "cert/cert.pem", "cert/key.pem")
	if err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}
