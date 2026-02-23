package util

import (
	"github.com/golang-jwt/jwt/v5"
	"time"
)

var jwtKey = []byte("your-secret-key") // 要放配置文件里

// GenerateToken 生成 JWT
func GenerateToken(playerID int, exp int) (string, error) {
	claims := jwt.MapClaims{
		"player_id": playerID,
		"exp":       time.Now().Add(time.Duration(exp) * time.Hour).Unix(), // 1天过期
		"iat":       time.Now().Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(jwtKey)
}

// ParseToken 解析 JWT
func ParseToken(tokenStr string) (*jwt.Token, jwt.MapClaims, error) {
	claims := jwt.MapClaims{}

	token, err := jwt.ParseWithClaims(tokenStr, claims, func(token *jwt.Token) (interface{}, error) {
		return jwtKey, nil
	})

	return token, claims, err
}
