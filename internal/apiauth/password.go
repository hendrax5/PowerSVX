package apiauth

import (
	"crypto/subtle"
	"fmt"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

const bcryptCost = bcrypt.DefaultCost

// NormalizePassword trims spaces and CR (common when .env is edited on Windows).
func NormalizePassword(password string) string {
	return strings.TrimSpace(strings.ReplaceAll(password, "\r", ""))
}

func HashPassword(password string) (string, error) {
	password = NormalizePassword(password)
	if password == "" {
		return "", fmt.Errorf("empty password")
	}
	b, err := bcrypt.GenerateFromPassword([]byte(password), bcryptCost)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func CheckPassword(hash, password string) bool {
	password = NormalizePassword(password)
	if hash == "" || password == "" {
		return false
	}
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
}

// PasswordEqual compares plaintext passwords in constant time when lengths match.
func PasswordEqual(a, b string) bool {
	a = NormalizePassword(a)
	b = NormalizePassword(b)
	if a == "" || b == "" || len(a) != len(b) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
