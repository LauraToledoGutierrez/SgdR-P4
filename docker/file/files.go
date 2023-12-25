package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	//go get github.com/dgrijalva/jwt-go
	"github.com/gin-gonic/gin" //go get github.com/gin-gonic/gin
	//go get github.com/google/uuid
)

const (
	VERSION         = "v1.0.0"
	USERS_PATH      = "users/"
	SHADOW_FILE     = ".shadow"
	TIME_EXPIRATION = 5
	// FALTA PONER CERTIFICADO
	CERT        = ""
	AUTH_SERVER = "https://10.0.2.3:5000/"
	KEY         = "b70a82b92875605defbeda92cfdabf0362aa4cac8e784b6445f2726a8a54abc0"
)

var TOKENS_DICT = make(map[string]string)

type Signup struct{}
type Login struct{}
type Version struct{}
type User struct{}
type Docs struct{}
type UserDir struct{}

// Check the authorization header for a valid token
func checkAuthorizationHeader(c *gin.Context, userID string) string {
	// Get the Authorization header from the request
	authHeader := c.GetHeader("Authorization")

	if authHeader == "" {
		c.JSON(400, gin.H{"error": "Authorization header must be: token <user-auth-token>"})
		return ""
	}
	headerParts := strings.Split(authHeader, "")
	if len(headerParts) != 2 || headerParts[0] != "token" {
		c.JSON(400, gin.H{"message": "Authorization header must be: token <user-auth-token>"})
		return ""
	}
	return headerParts[1]
}

func (u *User) get(c *gin.Context) {
	userID := c.Param("user_id")
	docID := c.Param("doc_id")

	token := checkAuthorizationHeader(c, userID)
	client := &http.Client{}
	req, err := http.NewRequest("GET", AUTH_SERVER, nil)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create request"})
		return
	}

	query := req.URL.Query()
	query.Add("username", userID)
	query.Add("token", token)
	req.URL.RawQuery = query.Encode()

	resp, err := client.Do(req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to send request to auth server"})
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Token is not correct or user not found"})
		return
	}

	jsonFileName := USERS_PATH + userID + "/" + docID + ".json"
	if _, err := os.Stat(jsonFileName); os.IsNotExist(err) {
		c.JSON(http.StatusNotFound, gin.H{"message": "The file does not exist"})
		return
	}

	jsonFile, err := os.Open(jsonFileName)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal Server Error"})
		return
	}
	defer jsonFile.Close()

	var data interface{}
	decoder := json.NewDecoder(jsonFile)
	if err := decoder.Decode(&data); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal Server Error"})
		return
	}
	c.JSON(http.StatusOK, data)

}

func (u *User) post(c *gin.Context) {
	userID := c.Param("user_id")
	docID := c.Param("doc_id")

	token := checkAuthorizationHeader(c, userID)

	client := &http.Client{}
	req, err := http.NewRequest("GET", AUTH_SERVER, nil)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Failed to create request"})
		return
	}

	query := req.URL.Query()
	query.Add("username", userID)
	query.Add("token", token)
	req.URL.RawQuery = query.Encode()

	resp, err := client.Do(req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Failed to send request to auth server"})
		return
	}
	defer resp.Body.Close()

	userDir := filepath.Join(USERS_PATH, userID)
	if _, err := os.Stat(userDir); os.IsNotExist(err) {
		if err := os.Mkdir(userDir, 0755); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create user directory"})
			return
		}
	}

	jsonFileName := filepath.Join(userDir, docID+".json")
	if _, err := os.Stat(jsonFileName); err == nil {
		c.JSON(http.StatusMethodNotAllowed, gin.H{"error": "The file already exists"})
		return
	}

	var jsonContent map[string]interface{}
	if err := c.ShouldBindJSON(&jsonContent); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Wrong format of the file or missing 'doc_content'"})
		return
	}

	jsonData, err := json.Marshal(jsonContent)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to encode JSON"})
		return
	}

	if err := ioutil.WriteFile(jsonFileName, jsonData, 0644); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to write file"})
		return
	}

	fileInfo, err := os.Stat(jsonFileName)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get file info"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"size": fileInfo.Size()})
}

func (u *User) put(c *gin.Context) {

	userID := c.Param("user_id")
	docID := c.Param("doc_id")

	token := checkAuthorizationHeader(c, userID)

	client := &http.Client{}
	req, err := http.NewRequest("GET", AUTH_SERVER, nil)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Failed to create request"})
		return
	}

	query := req.URL.Query()
	query.Add("username", userID)
	query.Add("token", token)
	req.URL.RawQuery = query.Encode()

	resp, err := client.Do(req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Failed to send request to auth server"})
		return
	}
	defer resp.Body.Close()

	jsonFileName := filepath.Join(USERS_PATH, userID, docID+".json")
	if _, err := os.Stat(jsonFileName); os.IsNotExist(err) {
		c.JSON(http.StatusNotFound, gin.H{"message": "The file does not exist"})
		return
	}

	var jsonInput map[string]interface{}
	if err := c.ShouldBindJSON(&jsonInput); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"message": "Wrong format of the file"})
		return
	}

	jsonData, err := json.Marshal(jsonInput)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Internal server error"})
		return
	}

	err = os.WriteFile(jsonFileName, jsonData, 0644)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Failed to write file"})
		return
	}

	fileInfo, err := os.Stat(jsonFileName)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Failed to get file info"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"size": fileInfo.Size()})
}

func (u *User) delete(c *gin.Context) {
	userID := c.Param("user_id")
	docID := c.Param("doc_id")

	token := checkAuthorizationHeader(c, userID)

	client := &http.Client{}
	req, err := http.NewRequest("GET", AUTH_SERVER, nil)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Failed to create request"})
		return
	}

	query := req.URL.Query()
	query.Add("username", userID)
	query.Add("token", token)
	req.URL.RawQuery = query.Encode()

	resp, err := client.Do(req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Failed to send request to auth server"})
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		c.JSON(http.StatusUnauthorized, gin.H{"message": "Token is not correct or user not found"})
		return
	}

	jsonFileName := filepath.Join(USERS_PATH, userID, docID+".json")
	if _, err := os.Stat(jsonFileName); os.IsNotExist(err) {
		c.JSON(http.StatusNotFound, gin.H{"message": "The file does not exist"})
		return
	}

	err = os.Remove(jsonFileName)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Failed to delete file"})
		return
	}

	c.JSON(http.StatusOK, gin.H{})
}

func (d *Docs) get(c *gin.Context) {
	userID := c.Param("user_id")

	token := checkAuthorizationHeader(c, userID)

	client := &http.Client{}
	req, err := http.NewRequest("GET", AUTH_SERVER, nil)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Failed to create request"})
		return
	}

	query := req.URL.Query()
	query.Add("username", userID)
	query.Add("token", token)
	req.URL.RawQuery = query.Encode()

	resp, err := client.Do(req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Failed to send request to auth server"})
		return
	}
	defer resp.Body.Close()

	allDocs := make(map[string]interface{})
	path, err := os.ReadDir(filepath.Join(USERS_PATH, userID))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Internal server error"})
		return
	}

	for _, entry := range path {
		fileName := entry.Name()
		filePath := fmt.Sprintf("%s%s/%s", USERS_PATH, userID, fileName)

		fileContent, err := os.ReadFile(filePath)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"message": "Internal server error"})
			return
		}

		var docContent map[string]interface{}
		if err := json.Unmarshal(fileContent, &docContent); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"message": "Internal server error"})
			return
		}

		allDocs[fileName[:len(fileName)-len(filepath.Ext(fileName))]] = docContent
	}

	c.JSON(http.StatusOK, allDocs)
}

func (ud *UserDir) post(c *gin.Context) {
	username := c.Query("username")
	if username == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Username is required"})
		return
	}

	userDir := filepath.Join(USERS_PATH, username)
	if err := os.Mkdir(userDir, 0755); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create user directory"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "User directory created"})
}

func main() {
	user := User{}
	docs := Docs{}
	userDir := UserDir{}

	router := gin.Default()

	router.GET("/:user_id/:doc_id", user.get)
	router.POST("/:user_id/:doc_id", user.post)
	router.PUT("/:user_id/:doc_id", user.put)
	router.DELETE("/:user_id/:doc_id", user.delete)
	router.GET("/alldocs/:user_id", docs.get)
	//ESTO HAY QUE MIRARLO
	router.POST("/userdir", userDir.post)

	//MIRAR ESTO MEJOR
	err := router.RunTLS(":443", "path/to/cert.pem", "path/to/key.pem")
	if err != nil {
		log.Fatal("Failed to start HTTPS server: ", err)
	}
}
