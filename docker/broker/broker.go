package main

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"log"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

//go get github.com/dgrijalva/jwt-go
//go get github.com/gin-gonic/gin
//go get github.com/google/uuid

const (
	VERSION         = "v1.0.0"
	USERS_PATH      = "users/"
	SHADOW_FILE     = ".shadow"
	TIME_EXPIRATION = 5
	// FALTA PONER CERTIFICADO
	CERT = ""

	FILES_SERVER = "https://10.0.2.4:5000"
	AUTH_SERVER  = "https://10.0.2.3:5000/"
	KEY          = "b70a82b92875605defbeda92cfdabf0362aa4cac8e784b6445f2726a8a54abc0"
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

func (v *Version) version(c *gin.Context) {
	c.JSON(200, gin.H{"version": VERSION})
}

func (s *Signup) post(c *gin.Context) {
	var jsonInput map[string]string
	if err := c.BindJSON(&jsonInput); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	// Aquí, jsonInput["username"] y jsonInput["password"] contienen los datos del usuario

	jsonData, err := json.Marshal(jsonInput)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error encoding JSON"})
		return
	}

	resp, err := http.Post(AUTH_SERVER, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to send request to auth server"})
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		var respError map[string]interface{}
		if err := json.NewDecoder(resp.Body).Decode(&respError); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to decode response from auth server"})
			return
		}
		c.JSON(resp.StatusCode, respError)
		return
	}

	var respData map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&respData); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to decode response from auth server"})
		return
	}

	c.JSON(http.StatusOK, respData)
}

func (l *Login) post(c *gin.Context) {
	var jsonInput map[string]string
	if err := c.BindJSON(&jsonInput); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	jsonData, err := json.Marshal(jsonInput)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error encoding JSON"})
		return
	}

	resp, err := http.Post(AUTH_SERVER, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to send request to auth server"})
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		var respError map[string]interface{}
		if err := json.NewDecoder(resp.Body).Decode(&respError); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to decode response from auth server"})
			return
		}
		c.JSON(resp.StatusCode, respError)
		return
	}

	var respData map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&respData); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to decode response from auth server"})
		return
	}

	c.JSON(http.StatusOK, respData)
}

func (u *User) get(c *gin.Context) {
	userID := c.Param("user_id")
	docID := c.Param("doc_id")

	token := checkAuthorizationHeader(c, userID)

	// Realizar la solicitud GET al servidor de archivos
	client := &http.Client{}
	req, err := http.NewRequest("GET", FILES_SERVER+"/"+userID+"/"+docID, nil)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create request"})
		return
	}

	req.Header.Add("Authorization", "token "+token)
	resp, err := client.Do(req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to send request to file server"})
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		var respError map[string]interface{}
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil || json.Unmarshal(body, &respError) != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to parse error response from file server"})
			return
		}
		c.JSON(resp.StatusCode, respError)
		return
	}

	var respData map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&respData); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to decode response from file server"})
		return
	}

	c.JSON(http.StatusOK, respData)
}

func (u *User) post(c *gin.Context) {
	userID := c.Param("user_id")
	docID := c.Param("doc_id")

	token := checkAuthorizationHeader(c, userID)

	var jsonInput map[string]interface{}
	if err := c.BindJSON(&jsonInput); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid JSON format"})
		return
	}

	docContent, exists := jsonInput["doc_content"]
	if !exists {
		c.JSON(http.StatusBadRequest, gin.H{"error": "doc_content is required"})
		return
	}

	jsonData, err := json.Marshal(docContent)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error encoding JSON"})
		return
	}

	// Realizar la solicitud POST al servidor de archivos
	client := &http.Client{}
	req, err := http.NewRequest("POST", FILES_SERVER+"/"+userID+"/"+docID, bytes.NewBuffer(jsonData))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create request"})
		return
	}

	req.Header.Add("Authorization", "token "+token)
	req.Header.Add("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to send request to file server"})
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		var respError map[string]interface{}
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil || json.Unmarshal(body, &respError) != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to parse error response from file server"})
			return
		}
		c.JSON(resp.StatusCode, respError)
		return
	}

	var respData map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&respData); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to decode response from file server"})
		return
	}

	c.JSON(http.StatusOK, respData)
}

func (u *User) put(c *gin.Context) {
	userID := c.Param("user_id")
	docID := c.Param("doc_id")

	token := checkAuthorizationHeader(c, userID)

	var jsonInput map[string]interface{}
	if err := c.BindJSON(&jsonInput); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid JSON format"})
		return
	}

	docContent, exists := jsonInput["doc_content"]
	if !exists {
		c.JSON(http.StatusBadRequest, gin.H{"error": "doc_content is required"})
		return
	}

	jsonData, err := json.Marshal(docContent)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error encoding JSON"})
		return
	}

	// Realizar la solicitud PUT al servidor de archivos
	client := &http.Client{}
	req, err := http.NewRequest("PUT", FILES_SERVER+"/"+userID+"/"+docID, bytes.NewBuffer(jsonData))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create request"})
		return
	}

	req.Header.Add("Authorization", "token "+token)
	req.Header.Add("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to send request to file server"})
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		var respError map[string]interface{}
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil || json.Unmarshal(body, &respError) != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to parse error response from file server"})
			return
		}
		c.JSON(resp.StatusCode, respError)
		return
	}

	var respData map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&respData); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to decode response from file server"})
		return
	}

	c.JSON(http.StatusOK, respData)
}

func (u *User) delete(c *gin.Context) {
	userID := c.Param("user_id")
	docID := c.Param("doc_id")

	token := checkAuthorizationHeader(c, userID)

	// Realizar la solicitud DELETE al servidor de archivos
	client := &http.Client{}
	req, err := http.NewRequest("DELETE", FILES_SERVER+"/"+userID+"/"+docID, nil)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create request"})
		return
	}

	req.Header.Add("Authorization", "token "+token)

	resp, err := client.Do(req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to send request to file server"})
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error en Auth Server"})
		return
	}

	var respData map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&respData); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to decode response from file server"})
		return
	}

	c.JSON(http.StatusOK, respData)
}

func (d *Docs) get(c *gin.Context) {
	userID := c.Param("user_id")

	token := checkAuthorizationHeader(c, userID)

	// Realizar la solicitud GET al servidor de archivos para obtener todos los documentos
	client := &http.Client{}
	req, err := http.NewRequest("GET", FILES_SERVER+"/"+userID+"/_all_docs", nil)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create request"})
		return
	}

	req.Header.Add("Authorization", "token "+token)

	resp, err := client.Do(req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to send request to file server"})
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error en Auth Server"})
		return
	}

	var respData map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&respData); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to decode response from file server"})
		return
	}

	c.JSON(http.StatusOK, respData)
}

func main() {
	router := gin.Default()

	version := Version{}
	signup := Signup{}
	login := Login{}
	user := User{}
	docs := Docs{}

	router.GET("/version", version.version)
	router.POST("/signup", signup.post)
	router.POST("/login", login.post)
	router.GET("/:user_id/:doc_id", user.get)
	router.POST("/:user_id/:doc_id", user.post)
	router.PUT("/:user_id/:doc_id", user.put)
	router.DELETE("/:user_id/:doc_id", user.delete)
	router.GET("/:user_id/_all_docs", docs.get)

	log.Fatal(router.RunTLS(":443", CERT, KEY))
}
