package main

import (
	"errors"

	"github.com/egoist/mygo"

	"github.com/qy/easyconnect/internal/store"
)

// keychainSecrets keeps the access points' creds in the system credential
// store: the macOS keychain, the Secret Service on Linux, the Credential
// Manager on Windows. A machine without one makes the fallback file store
// take over.
type keychainSecrets struct{}

func (keychainSecrets) Get(key string) (string, error) {
	value, err := mygo.Secrets.Get(key)
	switch {
	case errors.Is(err, mygo.ErrSecretNotFound):
		return "", store.ErrSecretNotFound
	case err != nil:
		return "", err
	}
	return string(value), nil
}

func (keychainSecrets) Set(key, value string) error {
	return mygo.Secrets.Set(key, []byte(value))
}

func (keychainSecrets) Delete(key string) error {
	return mygo.Secrets.Delete(key)
}
