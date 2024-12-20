package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"github.com/coreos/go-oidc"
	"golang.org/x/oauth2"
)

// Replace with your OIDC provider settings
const (
	clientID     = "oidc-client"
	clientSecret = "BimPY6GrQCX2cYPJi3b1jxxAlci2/cS"
	redirectURL  = "http://localhost:8088/callback"
	issuerURL    = "https://92a29d075154.ngrok.app/oidc" // Replace with your provider's issuer URL
)

var (
	provider     *oidc.Provider
	oauth2Config oauth2.Config
	verifier     *oidc.IDTokenVerifier
)

func main() {
	ctx := context.Background()

	// Initialize OIDC provider
	var err error
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
		Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
	}

	// Create an ID token verifier
	verifier = provider.Verifier(&oidc.Config{ClientID: clientID})

	// Set up HTTP handlers
	http.HandleFunc("/", handleHome)
	http.HandleFunc("/login", handleLogin)
	http.HandleFunc("/callback", handleCallback)

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
	http.Redirect(w, r, oauth2Config.AuthCodeURL("12345678910"), http.StatusFound)
}

func handleCallback(w http.ResponseWriter, r *http.Request) {
	ctx := context.Background()

	// Verify state
	if r.URL.Query().Get("state") != "12345678910" {
		http.Error(w, "State did not match", http.StatusBadRequest)
		return
	}

	// Exchange code for token
	oauth2Token, err := oauth2Config.Exchange(ctx, r.URL.Query().Get("code"))
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
		"token":  rawIDToken,
		"claims": claims,
	}

	// Write the response as JSON
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		http.Error(w, "Failed to encode response: "+err.Error(), http.StatusInternalServerError)
		return
	}
}
