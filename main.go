package main

import (
	"crypto/rsa"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/dgrijalva/jwt-go"
	uuid "github.com/satori/go.uuid"
)

type User struct {
	Data Data `json:"data"`
}

type Data struct {
	Attributes Attributes `json:"attributes"`
}

type Attributes struct {
	Username string `json:"username"`
	Email    string `json:"email"`
	FullName string `json:"fullName"`
}

type Result struct {
	Tokens []TokenResult `json:"tokens"`
}

type TokenResult struct {
	UUID  string `json:"uuid"`
	Token string `json:"token"`
}

func main() {
	keyLoc := flag.String("key", "foo", "private key location")
	userIDLoc := flag.String("users", "foo", "user UUIDs location")
	sessionSate := flag.String("session", "foo", "session state")
	saveTo := flag.String("saveTo", "foo", "File to save the result to")
	flag.Parse()

	fmt.Printf("Key location: %s\n", *keyLoc)
	fmt.Printf("User UUIDs location: %s\n", *userIDLoc)
	fmt.Printf("Session State: %s\n\n", *sessionSate)
	fmt.Printf("File to save the result to: %s\n\n", *saveTo)

	key, err := ioutil.ReadFile(*keyLoc)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Key: %s\n", string(key))

	privateKey, err := jwt.ParseRSAPrivateKeyFromPEM(key)
	if err != nil {
		panic(err)
	}

	userUUIDs, err := ioutil.ReadFile(*userIDLoc)
	if err != nil {
		panic(err)
	}
	ids := strings.Split(string(userUUIDs), "\n")
	var indx int
	result := Result{}
	tokens := []TokenResult{}
	for _, id := range ids {
		if len(id) > 2 {
			user, err := loadUser(id)
			if err != nil {
				panic(err)
			}
			indx++
			fmt.Printf("User %v: %s, %s, %s\n", indx, user.Data.Attributes.Username, user.Data.Attributes.Email, user.Data.Attributes.FullName)
			token, err := generateToken(privateKey, user, id, *sessionSate)
			if err != nil {
				panic(err)
			}
			tokens = append(tokens, TokenResult{UUID: id, Token: token})
		}
	}
	result.Tokens = tokens

	b, err := json.MarshalIndent(result, "", "    ")
	if err != nil {
		panic(err)
	}
	ioutil.WriteFile(*saveTo, b, 0644)
	fmt.Printf("Users: %v\n", indx)
}

type Token struct {
	Data Data `json:"data"`
}

func generateToken(key *rsa.PrivateKey, user User, userID string, session string) (string, error) {
	token := jwt.New(jwt.SigningMethodRS256)
	token.Header["kid"] = "0lL0vXs9YRVqZMowyw8uNLR_yr0iFaozdQk9rzq2OVU"

	token.Claims.(jwt.MapClaims)["jti"] = uuid.NewV4().String()
	token.Claims.(jwt.MapClaims)["exp"] = 1515627761
	token.Claims.(jwt.MapClaims)["nbf"] = 0
	token.Claims.(jwt.MapClaims)["iat"] = 1513035761
	token.Claims.(jwt.MapClaims)["iss"] = "https://sso.openshift.io/auth/realms/fabric8"
	token.Claims.(jwt.MapClaims)["aud"] = "fabric8-online-platform"
	token.Claims.(jwt.MapClaims)["sub"] = userID
	token.Claims.(jwt.MapClaims)["typ"] = "Bearer"
	token.Claims.(jwt.MapClaims)["azp"] = "fabric8-online-platform"
	token.Claims.(jwt.MapClaims)["auth_time"] = 1513035761
	token.Claims.(jwt.MapClaims)["session_state"] = session
	token.Claims.(jwt.MapClaims)["acr"] = "1"
	token.Claims.(jwt.MapClaims)["approved"] = "true"
	token.Claims.(jwt.MapClaims)["name"] = user.Data.Attributes.FullName
	token.Claims.(jwt.MapClaims)["company"] = ""
	token.Claims.(jwt.MapClaims)["preferred_username"] = user.Data.Attributes.Username
	token.Claims.(jwt.MapClaims)["given_name"] = ""
	token.Claims.(jwt.MapClaims)["family_name"] = ""
	token.Claims.(jwt.MapClaims)["email"] = user.Data.Attributes.Email

	//	token.Claims.(jwt.MapClaims)["iat"] = time.Now().Unix()
	token.Claims.(jwt.MapClaims)["allowed-origins"] = []string{
		"http://auth.openshift.io",
		"http://api.openshift.io",
		"https://openshift.io",
		"http://localhost:3000",
		"https://auth.openshift.io",
		"https://api.openshift.io"}

	realmAccess := make(map[string]interface{})
	realmAccess["roles"] = []string{"uma_authorization"}
	token.Claims.(jwt.MapClaims)["realm_access"] = realmAccess

	resourceAccess := make(map[string]interface{})
	broker := make(map[string]interface{})
	broker["roles"] = []string{"read-token"}
	resourceAccess["broker"] = broker

	account := make(map[string]interface{})
	account["roles"] = []string{"manage-account", "manage-account-links", "view-profile"}
	resourceAccess["account"] = account

	token.Claims.(jwt.MapClaims)["resource_access"] = resourceAccess

	tokenStr, err := token.SignedString(key)
	if err != nil {
		return "", err
	}
	return tokenStr, nil
}

func loadUser(id string) (User, error) {
	var user User
	req, err := http.NewRequest("GET", "https://auth.openshift.io/api/users/"+id, nil)
	if err != nil {
		return user, err
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return user, err
	}
	defer res.Body.Close()
	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return user, err
	}
	if res.StatusCode != http.StatusOK {
		return user, errors.New("Status is not 200 OK: " + res.Status)
	}
	err = json.Unmarshal(body, &user)

	return user, err
}
