package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"github.com/coreos/go-oidc"
	"golang.org/x/oauth2"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
)

// Replace with your OIDC provider settings
const (
	clientID     = "client-qj7zvvcmdn"
	clientSecret = "secret-zn4h8n6khb482qk459vjwwwhjwqkqjfdght7cnwtrbmd7dqs74cqh5lk"
	redirectURL  = "http://localhost:8088/callback"
	issuerURL    = "https://ec2-35-179-134-209.eu-west-2.compute.amazonaws.com/oidc" // Replace with your provider's issuer URL
)

var (
	provider     *oidc.Provider
	oauth2Config oauth2.Config
	verifier     *oidc.IDTokenVerifier
	codeVerifier string
)

func main() {
	ctx := context.Background()

	// Initialize OIDC provider
	var err error
	insecureTransport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	insecureClient := &http.Client{
		Transport: insecureTransport,
	}
	ctx = oidc.ClientContext(ctx, insecureClient)
	provider, err = oidc.NewProvider(ctx, issuerURL)

	if err != nil {
		log.Fatalf("Failed to get provider: %v", err)
	}

	// Configure OAuth2 client
	oauth2Config = oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		Endpoint:     provider.Endpoint(),
		Scopes:       []string{oidc.ScopeOpenID, "profile", "offline_access"},
	}

	// Create an ID token verifier
	verifier = provider.Verifier(&oidc.Config{ClientID: clientID})

	// Set up HTTP handlers
	http.HandleFunc("/", handleHome)
	http.HandleFunc("/login", handleLogin)
	http.HandleFunc("/callback", handleCallback)
	http.HandleFunc("/refresh", refreshToken)

	log.Println("Server starting on http://localhost:8088")
	log.Fatal(http.ListenAndServe(":8088", nil))
}

func handleHome(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, `<html><body>
	<h1>Welcome to OIDC Login Example</h1>
	<a href="/login">Log in</a>
	</body></html>`)
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	// Redirect user to the OIDC provider's login page
	codeVerifier = oauth2.GenerateVerifier()
	http.Redirect(w, r, oauth2Config.AuthCodeURL("12345678910", oauth2.S256ChallengeOption(codeVerifier)), http.StatusFound)
}

func handleCallback(w http.ResponseWriter, r *http.Request) {
	ctx := context.Background()

	// Verify state
	if r.URL.Query().Get("state") != "12345678910" {
		http.Error(w, "State did not match", http.StatusBadRequest)
		return
	}

	// Exchange code for token
	oauth2Token, err := oauth2Config.Exchange(ctx, r.URL.Query().Get("code"), oauth2.VerifierOption(codeVerifier))
	if err != nil {
		http.Error(w, "Failed to exchange token: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Extract and verify ID Token
	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		http.Error(w, "No id_token field in token response", http.StatusInternalServerError)
		return
	}

	idToken, err := verifier.Verify(ctx, rawIDToken)
	if err != nil {
		http.Error(w, "Failed to verify ID Token: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Parse claims
	var claims map[string]interface{}
	if err := idToken.Claims(&claims); err != nil {
		http.Error(w, "Failed to parse claims: "+err.Error(), http.StatusInternalServerError)
		return
	}

	response := map[string]interface{}{
		"token":         rawIDToken,
		"claims":        claims,
		"refresh_token": oauth2Token.Extra("refresh_token").(string),
	}

	// Write the response as JSON
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		http.Error(w, "Failed to encode response: "+err.Error(), http.StatusInternalServerError)
		return
	}
}

func refreshToken(w http.ResponseWriter, r *http.Request) {
	data := url.Values{}
	data.Set("grant_type", "refresh_token")
	data.Set("refresh_token", r.URL.Query().Get("refresh_token"))
	data.Set("client_id", clientID)
	data.Set("client_secret", clientSecret)

	req, err := http.NewRequest("POST", provider.Endpoint().TokenURL, bytes.NewBufferString(data.Encode()))
	if err != nil {
		fmt.Printf("Failed to create HTTP request: %v\n", err)
		return
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("Failed to send HTTP request: %v\n", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := ioutil.ReadAll(resp.Body)
		fmt.Printf("Failed to refresh token: %s\nResponse: %s\n", resp.Status, string(body))
		return
	}

	//	body, _ := ioutil.ReadAll(resp.Body)
	//	fmt.Printf("Refresh token: %s\n", string(body))

	var tokenResponse struct {
		AccessToken  string `json:"access_token"`
		IDToken      string `json:"id_token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresIn    int    `json:"expires_in"`
		TokenType    string `json:"token_type"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&tokenResponse); err != nil {
		fmt.Printf("Failed to decode token response: %v\n", err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(tokenResponse); err != nil {
		http.Error(w, "Failed to encode response: "+err.Error(), http.StatusInternalServerError)
		return
	}
}
