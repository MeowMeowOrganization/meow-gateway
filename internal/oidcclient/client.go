// Package oidcclient delegates OIDC discovery, ID-token signature and claim
// validation to maintained protocol libraries; it does NOT parse JWTs itself.
package oidcclient

import (
	"context"
	"errors"
	"fmt"
	"net/url"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

type Client struct {
	oauth    oauth2.Config
	verifier *oidc.IDTokenVerifier
}

func New(ctx context.Context, issuer, clientID, clientSecret, callbackURL string) (*Client, error) {
	if issuer == "" || clientID == "" || clientSecret == "" {
		return nil, errors.New("OIDC issuer, client id and secret are mandatory")
	}
	u, err := url.Parse(callbackURL)
	if err != nil || u == nil || u.Fragment != "" || u.RawQuery != "" || u.Path != "/auth/callback" {
		return nil, errors.New("invalid OIDC callback URL")
	}
	provider, err := oidc.NewProvider(ctx, issuer)
	if err != nil {
		return nil, fmt.Errorf("OIDC provider discovery: %w", err)
	}
	return &Client{oauth: oauth2.Config{ClientID: clientID, ClientSecret: clientSecret, RedirectURL: callbackURL, Endpoint: provider.Endpoint(), Scopes: []string{oidc.ScopeOpenID}}, verifier: provider.Verifier(&oidc.Config{ClientID: clientID})}, nil
}
func (c *Client) LoginURL(state, nonce, challenge string) string {
	return c.oauth.AuthCodeURL(state, oauth2.SetAuthURLParam("nonce", nonce), oauth2.SetAuthURLParam("code_challenge", challenge), oauth2.SetAuthURLParam("code_challenge_method", "S256"))
}
func (c *Client) Exchange(ctx context.Context, code, verifier, expectedNonce string) (string, error) {
	token, err := c.oauth.Exchange(ctx, code, oauth2.VerifierOption(verifier))
	if err != nil {
		return "", err
	}
	raw, ok := token.Extra("id_token").(string)
	if !ok || raw == "" {
		return "", errors.New("OIDC token response missing ID token")
	}
	verified, err := c.verifier.Verify(ctx, raw)
	if err != nil {
		return "", err
	}
	if expectedNonce == "" || verified.Nonce != expectedNonce || verified.Subject == "" {
		return "", errors.New("invalid ID-token nonce or subject")
	}
	return verified.Subject, nil
}
