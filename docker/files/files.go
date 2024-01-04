package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

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
	CERT        = "certs/file-cert.pem"
	AUTH_SERVER = "https://10.0.2.3:5000/"
	AUTH_CERT   = "certs/auth.ssl.crt"
	KEY         = "keys/file-key.pem"
	IP_HOST     = "10.0.2.4"
	PORT        = "5000"
)

var TOKENS_DICT = make(map[string]string)

type Signup struct{}
type Login struct{}
type Version struct{}
type User struct{}
type Docs struct{}
type UserDir struct{}

func checkAuthorizationHeader(c *gin.Context) string {
	authHeader := c.GetHeader("Authorization")
	if authHeader == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Authorization header is required"})
		return ""
	}
	headerParts := strings.Split(authHeader, " ")
	if len(headerParts) != 2 || headerParts[0] != "token" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Authorization header must be: token <user-auth-token"})
		return ""
	}
	return headerParts[1]
}

func createTLSClient(certFile string) (*http.Client, error) {
	caCert, err := ioutil.ReadFile(certFile)
	if err != nil {
		return nil, err
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)
	tlsConfig := &tls.Config{RootCAs: caCertPool}
	return &http.Client{
		Transport: &http.Transport{TLSClientConfig: tlsConfig},
		Timeout:   10 * time.Second,
	}, nil
}

func makeHTTPRequest(client *http.Client, method, url string, token string, body []byte) (*http.Response, error) {
	req, err := http.NewRequest(method, url, bytes.NewBuffer(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "token "+token)
	req.Header.Set("Content-Type", "application/json")
	return client.Do(req)
}

func handleHTTPResponse(c *gin.Context, resp *http.Response) {
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	if resp.StatusCode == http.StatusOK {
		var result map[string]interface{}
		if err := json.Unmarshal(body, &result); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, result)
	} else {
		var errorResponse map[string]interface{}
		if err := json.Unmarshal(body, &errorResponse); err == nil {
			c.JSON(resp.StatusCode, errorResponse)
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Error processing response"})
		}
	}
}

func (u *User) get(c *gin.Context) {
	userID := c.Param("user_id")
	docID := c.Param("doc_id")

	token := checkAuthorizationHeader(c)

	// Realizar solicitud de verificación de token al servidor AUTH
	client, err := createTLSClient(AUTH_CERT)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	resp, err := makeHTTPRequest(client, "GET", AUTH_SERVER+"checking", token, nil)
	if err != nil || resp.StatusCode != http.StatusOK {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Token is not correct"})
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

	token := checkAuthorizationHeader(c)

	client, err := createTLSClient(AUTH_CERT)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	resp, err := makeHTTPRequest(client, "GET", AUTH_SERVER+"checking", token, nil)
	if err != nil || resp.StatusCode != http.StatusOK {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Token is not correct"})
		return
	}

	if _, err := os.Stat(USERS_PATH + userID + "/" + docID + ".json"); !os.IsNotExist(err) {
		c.JSON(405, gin.H{"message": "The file already exists, use put to update"})
		return
	}

	// Parse JSON input from the request body
	var jsonInput map[string]interface{}
	if err := c.BindJSON(&jsonInput); err != nil {
		c.JSON(400, gin.H{"message": "Wrong format of the file"})
		return
	}

	// Extract document content from the JSON input
	docContent, exists := jsonInput["doc_content"]
	if !exists {
		c.JSON(400, gin.H{"message": "Argument must be 'doc_content'"})
		return
	}

	// Construct the file path for the JSON file
	jsonFileName := USERS_PATH + userID + "/" + docID + ".json"
	// Marshal the document content to JSON format
	jsonString, err := json.Marshal(docContent)
	if err != nil {
		c.JSON(500, gin.H{"message": "Internal server error"})
		return
	}

	// Write the JSON content to the file
	err = ioutil.WriteFile(jsonFileName, jsonString, 0644)
	if err != nil {
		c.JSON(500, gin.H{"message": "Internal server error"})
		return
	}

	// Get information about the created file
	fileInfo, err := os.Stat(jsonFileName)
	if err != nil {
		c.JSON(500, gin.H{"message": "Internal server error"})
		return
	}
	c.JSON(200, gin.H{"size": fileInfo.Size()})
}

func (u *User) put(c *gin.Context) {

	userID := c.Param("user_id")
	docID := c.Param("doc_id")

	token := checkAuthorizationHeader(c)

	client, err := createTLSClient(AUTH_CERT)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	resp, err := makeHTTPRequest(client, "GET", AUTH_SERVER+"checking", token, nil)
	if err != nil || resp.StatusCode != http.StatusOK {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Token is not correct"})
		return
	}

	jsonFilePath := fmt.Sprintf("%s%s/%s.json", USERS_PATH, userID, docID)

	// Check if the file exists
	if _, err := os.Stat(jsonFilePath); os.IsNotExist(err) {
		c.JSON(404, gin.H{"message": "The file does not exist"})
		return
	}

	// Read the current content of the file
	currentContent, err := ioutil.ReadFile(jsonFilePath)
	if err != nil {
		c.JSON(500, gin.H{"message": "Internal server error"})
		return
	}

	// Decode the current content of the file into a map
	var currentJSON map[string]interface{}
	err = json.Unmarshal(currentContent, &currentJSON)
	if err != nil {
		c.JSON(500, gin.H{"message": "Internal server error"})
		return
	}

	// REad the new content from the request body
	var newContent map[string]interface{}
	if err := c.BindJSON(&newContent); err != nil {
		c.JSON(400, gin.H{"message": "Wrong format of the file"})
		return
	}

	// Update the current content with the new content
	for key, value := range newContent {
		currentJSON[key] = value
	}

	// Encode the new content
	newContentString, err := json.Marshal(currentJSON)
	if err != nil {
		c.JSON(500, gin.H{"message": "Internal server error"})
		return
	}

	// Write the new content to the existing file
	err = ioutil.WriteFile(jsonFilePath, newContentString, 0644)
	if err != nil {
		c.JSON(500, gin.H{"message": "Internal server error"})
		return
	}

	// Get information about the update file
	fileInfo, err := os.Stat(jsonFilePath)
	if err != nil {
		c.JSON(500, gin.H{"message": "Internal server error"})
		return
	}
	c.JSON(200, gin.H{"size": fileInfo.Size()})
}

func (u *User) delete(c *gin.Context) {
	userID := c.Param("user_id")
	docID := c.Param("doc_id")

	token := checkAuthorizationHeader(c)

	client, err := createTLSClient(AUTH_CERT)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	resp, err := makeHTTPRequest(client, "GET", AUTH_SERVER+"checking", token, nil)
	if err != nil || resp.StatusCode != http.StatusOK {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Token is not correct"})
		return
	}
	jsonFilePath := fmt.Sprintf("%s%s/%s.json", USERS_PATH, userID, docID)

	// Check if the file exists
	if _, err := os.Stat(jsonFilePath); os.IsNotExist(err) {
		c.JSON(404, gin.H{"message": "The file does not exist"})
		return
	}

	err = os.Remove(jsonFilePath)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Failed to delete file"})
		return
	}

	c.JSON(http.StatusOK, gin.H{})
}

func (d *Docs) get(c *gin.Context) {
	userID := c.Param("user_id")

	token := checkAuthorizationHeader(c)

	client, err := createTLSClient(AUTH_CERT)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	resp, err := makeHTTPRequest(client, "GET", AUTH_SERVER+"checking", token, nil)
	if err != nil || resp.StatusCode != http.StatusOK {
		c.JSON(resp.StatusCode, gin.H{"error": "Token is not correct"})
		return
	}

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

	fmt.Println("Practica 4 - Laura Toledo Gutierrez")

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
	router.POST("/space", userDir.post)

	//MIRAR ESTO MEJOR
	address := fmt.Sprintf("%s:%s", IP_HOST, PORT)
	log.Fatal(router.RunTLS(address, CERT, KEY))
}
