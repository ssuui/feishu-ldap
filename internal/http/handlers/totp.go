package handlers

import (
	"log"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/pquerna/otp/totp"

	"feishu-ldap-server/internal/common"
	"feishu-ldap-server/internal/contact"
	"feishu-ldap-server/internal/http/middleware"
	"feishu-ldap-server/internal/session"
)

type TOTPHandler struct {
	cache *contact.Cache
}

func NewTOTPHandler(cache *contact.Cache) *TOTPHandler {
	return &TOTPHandler{
		cache: cache,
	}
}

func (h *TOTPHandler) getUserFromSession(sess *session.Session) *contact.LDAPUser {
	if sess == nil {
		return nil
	}

	if sess.UserID != "" {
		if user := h.cache.GetUserByUserID(sess.UserID); user != nil {
			return user
		}
	}

	if sess.UnionID != "" {
		if user := h.cache.GetUserByUnionID(sess.UnionID); user != nil {
			return user
		}
	}

	return nil
}

func (h *TOTPHandler) HandleGetCode(c *gin.Context) {
	sess := middleware.GetSession(c)
	if sess == nil {
		common.Unauthorized(c, "")
		return
	}

	user := h.getUserFromSession(sess)
	if user == nil {
		log.Printf("[TOTP] 未找到用户: user_id=%s, union_id=%s", sess.UserID, sess.UnionID)
		common.NotFound(c, "用户未在通讯录中")
		return
	}

	if user.TOTPSecret == "" {
		log.Printf("[TOTP] 用户缺少 TOTP 秘钥: user_id=%s", user.UserID)
		common.NotFound(c, "用户未配置 TOTP")
		return
	}

	now := time.Now()
	code, err := totp.GenerateCode(user.TOTPSecret, now)
	if err != nil {
		log.Printf("[TOTP] 生成验证码失败: %v", err)
		common.InternalError(c, "生成验证码失败")
		return
	}

	expiresAt := now.Add(30 * time.Second).Truncate(30 * time.Second).Add(30 * time.Second)
	remainingSeconds := expiresAt.Sub(now).Seconds()

	log.Printf("[TOTP] 生成验证码: user_id=%s, name=%s", user.UserID, user.Name)

	common.Success(c, gin.H{
		"code":         code,
		"expires_in":   int(remainingSeconds),
		"user_id":      user.UserID,
		"user_name":    user.Name,
		"generated_at": now.Format(time.RFC3339),
		"expires_at":   expiresAt.Format(time.RFC3339),
	})
}

func (h *TOTPHandler) HandleGetUserInfo(c *gin.Context) {
	sess := middleware.GetSession(c)
	if sess == nil {
		common.Unauthorized(c, "")
		return
	}

	user := h.getUserFromSession(sess)
	if user == nil {
		common.NotFound(c, "用户未在通讯录中")
		return
	}

	common.Success(c, gin.H{
		"user_id":  user.UserID,
		"union_id": user.UnionID,
		"name":     user.Name,
		"mobile":   user.Mobile,
		"email":    user.Email,
		"has_totp": user.TOTPSecret != "",
	})
}
