package middleware

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	"feishu-ldap-server/internal/session"
)

type ContextKey string

const (
	SessionKey ContextKey = "session"
)

func AuthRequired() gin.HandlerFunc {
	return func(c *gin.Context) {
		token := c.GetHeader("token")
		if token == "" {
			token = c.Query("token")
		}

		if token == "" {
			c.JSON(http.StatusUnauthorized, gin.H{
				"success": false,
				"message": "缺少认证 Token",
			})
			c.Abort()
			return
		}

		token = strings.TrimSpace(token)

		mgr := session.GetManager()
		if mgr == nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"success": false,
				"message": "会话管理器未初始化",
			})
			c.Abort()
			return
		}

		sess, valid := mgr.ValidateToken(token)
		if !valid {
			c.JSON(http.StatusUnauthorized, gin.H{
				"success": false,
				"message": "Token 无效或已过期",
			})
			c.Abort()
			return
		}

		c.Set(string(SessionKey), sess)
		c.Next()
	}
}

func GetSession(c *gin.Context) *session.Session {
	val, exists := c.Get(string(SessionKey))
	if !exists {
		return nil
	}
	sess, ok := val.(*session.Session)
	if !ok {
		return nil
	}
	return sess
}
