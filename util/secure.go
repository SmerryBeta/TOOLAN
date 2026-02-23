package util

import (
	"crypto/md5"
	"crypto/rand"
	"encoding/hex"
)

func GenerateSalt() string {
	bytes := make([]byte, 16) // 16 字节盐
	_, _ = rand.Read(bytes)
	return hex.EncodeToString(bytes)
}

func EncryptPassword(password, salt string) string {
	sum := md5.Sum([]byte(password + salt))
	return hex.EncodeToString(sum[:])
}

func VerifyPassword(inputPassword, salt, encrypted string) bool {
	return EncryptPassword(inputPassword, salt) == encrypted
}
