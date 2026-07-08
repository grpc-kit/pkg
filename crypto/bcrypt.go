package crypto

import "golang.org/x/crypto/bcrypt"

func BcryptHash(password string) (string, error) {
	pass, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}

	return string(pass), nil
}

func BcryptHashMust(password string) string {
	hashedPassword, err := BcryptHash(password)
	if err != nil {
		return ""
	}

	return hashedPassword
}

func BcryptCompare(hashedPassword, password string) error {
	return bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
}
