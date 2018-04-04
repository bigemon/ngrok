package auth

import (
	"testing"
)

func TestConfigAuth(t *testing.T) {
	path := "./ngrok-secrets"
	ac := NewConfigAuth(path)
	if userName, err := ac.Auth("test:123456"); err != nil {
		t.Fatal(err)
	} else {
		t.Log(userName)
	}
}
