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
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

// Constantes y variables globales
const (
	VERSION      = "v1.0.0"
	IP_HOST      = "10.0.1.4"
	PORT         = "5000"
	FILES_SERVER = "https://10.0.2.4:5000"
	FILES_CERT   = "certs/file-cert.ssl.crt"
	AUTH_SERVER  = "https://10.0.2.3:5000"
	AUTH_CERT    = "certs/auth-cert.ssl.crt"
	CERT_PEM     = "certs/broker-cert.ssl.crt"
	KEY_PEM      = "keys/broker-key.ssl.key"
	USERS        = "users/"
	MINUTES      = 5
)

var TOKENS_DICT = make(map[string]string)

type Credentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type Signup struct{}
type Login struct{}
type Version struct{}
type User struct{}
type Docs struct{}

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

func (v *Version) get(c *gin.Context) {
	c.JSON(200, gin.H{"version": VERSION})
}

func (s *Signup) post(c *gin.Context) {
	var jsonReq map[string]string
	if err := c.BindJSON(&jsonReq); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	requestData, _ := json.Marshal(jsonReq)

	client, err := createTLSClient(AUTH_CERT)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	resp, err := makeHTTPRequest(client, "POST", AUTH_SERVER, "", requestData)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer resp.Body.Close()

	handleHTTPResponse(c, resp)
}

func (l *Login) post(c *gin.Context) {
	var loginData struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	if err := c.BindJSON(&loginData); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Convertir datos de login a JSON para la petición
	requestData, err := json.Marshal(loginData)
	client, err := createTLSClient(AUTH_CERT)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	resp, err := makeHTTPRequest(client, "GET", AUTH_SERVER, "", requestData)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer resp.Body.Close()

	handleHTTPResponse(c, resp)
}

func (u *User) get(c *gin.Context) {
	user_id := c.Param("user_id")
	doc_id := c.Param("doc_id")

	token := checkAuthorizationHeader(c)

	client, err := createTLSClient(FILES_CERT)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	resp, err := makeHTTPRequest(client, "GET", FILES_SERVER+"/"+user_id+"/"+doc_id, token, nil)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer resp.Body.Close()

	handleHTTPResponse(c, resp)
}

func (u *User) post(c *gin.Context) {
	user_id := c.Param("user_id")
	doc_id := c.Param("doc_id")
	token := checkAuthorizationHeader(c)
	var jsonReq map[string]interface{}
	if err := c.BindJSON(&jsonReq); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	requestData, err := json.Marshal(jsonReq)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	client, err := createTLSClient(FILES_CERT)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	resp, err := makeHTTPRequest(client, "POST", FILES_SERVER+"/"+user_id+"/"+doc_id, token, requestData)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer resp.Body.Close()

	handleHTTPResponse(c, resp)
}
func (u *User) put(c *gin.Context) {
	user_id := c.Param("user_id")
	doc_id := c.Param("doc_id")
	token := checkAuthorizationHeader(c)

	var jsonReq map[string]interface{}
	if err := c.BindJSON(&jsonReq); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	requestData, err := json.Marshal(jsonReq)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	client, err := createTLSClient(FILES_CERT)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	resp, err := makeHTTPRequest(client, "PUT", FILES_SERVER+"/"+user_id+"/"+doc_id, token, requestData)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer resp.Body.Close()

	// Leer y manejar la respuesta
	handleHTTPResponse(c, resp)
}

func (u *User) delete(c *gin.Context) {
	user_id := c.Param("user_id")
	doc_id := c.Param("doc_id")
	token := checkAuthorizationHeader(c)

	client, err := createTLSClient(FILES_CERT)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	resp, err := makeHTTPRequest(client, "DELETE", FILES_SERVER+"/"+user_id+"/"+doc_id, token, nil)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer resp.Body.Close()

	handleHTTPResponse(c, resp)
}
func (d *Docs) get(c *gin.Context) {
	user_id := c.Param("user_id")
	token := checkAuthorizationHeader(c)

	client, err := createTLSClient(FILES_CERT)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	resp, err := makeHTTPRequest(client, "GET", FILES_SERVER+"/"+user_id+"/_all_docs", token, nil)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer resp.Body.Close()

	handleHTTPResponse(c, resp)
}

func main() {

	fmt.Println("Practica 4 - Laura Toledo Gutierrez")

	router := gin.Default()

	version := Version{}
	signup := Signup{}
	login := Login{}
	user := User{}
	docs := Docs{}

	router.GET("/version", version.get)
	router.POST("/signup", signup.post)
	router.POST("/login", login.post)
	router.GET("/:user_id/:doc_id", user.get)
	router.POST("/:user_id/:doc_id", user.post)
	router.PUT("/:user_id/:doc_id", user.put)
	router.DELETE("/:user_id/:doc_id", user.delete)
	router.GET("/:user_id/_all_docs", docs.get)

	address := fmt.Sprintf("%s:%s", IP_HOST, PORT)
	log.Fatal(router.RunTLS(address, CERT_PEM, KEY_PEM))
}
