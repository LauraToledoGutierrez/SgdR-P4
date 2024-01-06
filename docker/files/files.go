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

	"github.com/gin-gonic/gin" //go get github.com/gin-gonic/gin
)

const (
	VERSION         = "v1.0.0"
	USERS_PATH      = "users/"
	SHADOW_FILE     = ".shadow"
	TIME_EXPIRATION = 5
	CERT            = "certs/files-cert.ssl.crt"
	AUTH_SERVER     = "https://10.0.2.3:5000/"
	AUTH_CERT       = "certs/auth-cert.ssl.crt"
	KEY             = "keys/files-key.ssl.key"
	IP_HOST         = "10.0.2.4"
	PORT            = "5000"
)

var TOKENS_DICT = make(map[string]string)

type Signup struct{}
type Login struct{}
type Version struct{}
type User struct{}
type Docs struct{}
type UserDir struct{}

// AUXILIARY FUNCTIONS

// Verify and process the authorization header in an http request
func checkAuthorizationHeader(c *gin.Context) string {
	// Obtain the value of authorization header
	authHeader := c.GetHeader("Authorization")
	if authHeader == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Authorization header is required"})
		return ""
	}
	// Divide the authorization header into its parts using a black space as a delimiter
	headerParts := strings.Split(authHeader, " ")
	if len(headerParts) != 2 || headerParts[0] != "token" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Authorization header must be: token <user-auth-token"})
		return ""
	}
	return headerParts[1]
}

// Create a HTTP client that uses a custom TLS certificate to make secure requests over HTTPS
func createTLSClient(certFile string) (*http.Client, error) {
	// Read the certificate
	caCert, err := ioutil.ReadFile(certFile)
	if err != nil {
		return nil, err
	}
	// Create a certificate pool and add the contets of the certificate files to this pool
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)
	tlsConfig := &tls.Config{RootCAs: caCertPool}
	return &http.Client{
		Transport: &http.Transport{TLSClientConfig: tlsConfig},
		Timeout:   10 * time.Second,
	}, nil
}

// Make a HTTP request using a custom HTTP client
func makeHTTPRequest(client *http.Client, method, url string, token string, body []byte) (*http.Response, error) {
	// Create a new request
	req, err := http.NewRequest(method, url, bytes.NewBuffer(body))
	if err != nil {
		return nil, err
	}
	// Configure the request header
	req.Header.Set("Authorization", "token "+token)
	req.Header.Set("Content-Type", "application/json")
	// Make the HTTP request
	return client.Do(req)
}

// Handle the HTTP response
func handleHTTPResponse(c *gin.Context, resp *http.Response) {
	// Read the HTTP response body
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	// Respond to the client according to the status code
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

// USER -> GET user data based on user id and document id
func (u *User) get(c *gin.Context) {
	// Extract user id and document id from the request parameters
	userID := c.Param("user_id")
	docID := c.Param("doc_id")

	token := checkAuthorizationHeader(c)

	// Create HTTP client with TLS certificate
	client, err := createTLSClient(AUTH_CERT)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	// Make the request token verification to the authentication server
	resp, err := makeHTTPRequest(client, "GET", AUTH_SERVER+"checking", token, nil)
	if err != nil || resp.StatusCode != http.StatusOK {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Token is not correct"})
		return
	}

	// Create json name
	jsonFileName := USERS_PATH + userID + "/" + docID + ".json"
	if _, err := os.Stat(jsonFileName); os.IsNotExist(err) {
		c.JSON(http.StatusNotFound, gin.H{"message": "The file does not exist"})
		return
	}
	// Open json file
	jsonFile, err := os.Open(jsonFileName)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal Server Error"})
		return
	}
	defer jsonFile.Close()

	// Read and decode json
	var data interface{}
	decoder := json.NewDecoder(jsonFile)
	if err := decoder.Decode(&data); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal Server Error"})
		return
	}
	c.JSON(http.StatusOK, data)
}

// USER -> Post, handle creating a new document for a user
func (u *User) post(c *gin.Context) {
	userID := c.Param("user_id")
	docID := c.Param("doc_id")

	token := checkAuthorizationHeader(c)

	// Create HTTP client with TLS certificate
	client, err := createTLSClient(AUTH_CERT)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// Make the request token verification to the authentication server
	resp, err := makeHTTPRequest(client, "GET", AUTH_SERVER+"checking", token, nil)
	if err != nil || resp.StatusCode != http.StatusOK {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Token is not correct"})
		return
	}

	// Verify and create directory
	dirPath := USERS_PATH + userID
	if _, err := os.Stat(dirPath); os.IsNotExist(err) {
		if err := os.MkdirAll(dirPath, 0755); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Unable to create directory"})
			return
		}
	}

	// Construct the file path for the json file
	jsonFileName := dirPath + "/" + docID + ".json"
	if _, err := os.Stat(jsonFileName); !os.IsNotExist(err) {
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

	// Marshal the document content to JSON format
	jsonString, err := json.Marshal(docContent)
	if err != nil {
		c.JSON(500, gin.H{"message": "Internal server error"})
		return
	}

	// Write the JSON content to the file
	err = ioutil.WriteFile(jsonFileName, jsonString, 0644)
	if err != nil {
		c.JSON(500, gin.H{"message": err.Error()})
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

// USER -> Put, handle updating the content of an existing document for a user
func (u *User) put(c *gin.Context) {

	userID := c.Param("user_id")
	docID := c.Param("doc_id")

	token := checkAuthorizationHeader(c)

	// Create HTTP client with TLS certificate
	client, err := createTLSClient(AUTH_CERT)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// Make the request token verification to the authentication server
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

// USER -> Delete, handle deleting a document for a user
func (u *User) delete(c *gin.Context) {
	userID := c.Param("user_id")
	docID := c.Param("doc_id")

	token := checkAuthorizationHeader(c)

	// Create HTTP client with TLS certificate
	client, err := createTLSClient(AUTH_CERT)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// Make the request token verification to the authentication server
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

	// Remove the file
	err = os.Remove(jsonFilePath)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Failed to delete file"})
		return
	}

	c.JSON(http.StatusOK, gin.H{})
}

// ALLDOCS -> GET, hadle retrieving all documents for a user
func (d *Docs) get(c *gin.Context) {
	userID := c.Param("user_id")

	token := checkAuthorizationHeader(c)

	// Create HTTP client with TLS certificate
	client, err := createTLSClient(AUTH_CERT)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	// Make the request token verification to the authentication server
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
	// Browse through all files in the user's document directory
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
		// Add the document content to the map of all documents
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

	// Define instances
	user := User{}
	docs := Docs{}

	// Set up gin router
	router := gin.Default()

	// Define Endpoints
	router.GET("/:user_id/:doc_id", user.get)
	router.POST("/:user_id/:doc_id", user.post)
	router.PUT("/:user_id/:doc_id", user.put)
	router.DELETE("/:user_id/:doc_id", user.delete)
	router.GET("/alldocs/:user_id", docs.get)

	userDir := UserDir{}
	router.POST("/space", userDir.post)

	// Run gin server with cert and key
	address := fmt.Sprintf("%s:%s", IP_HOST, PORT)
	log.Fatal(router.RunTLS(address, CERT, KEY))
}
