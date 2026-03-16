package handlers

import (
	"log"
	"net/http"
	"net/url"

	"github.com/gin-gonic/gin"

	"feishu-ldap-server/config"
	"feishu-ldap-server/internal/common"
	"feishu-ldap-server/internal/feishu"
	"feishu-ldap-server/internal/session"
)

type AuthHandler struct {
	cfg     *config.Config
	client  *feishu.Client
	session *session.Manager
}

func NewAuthHandler(cfg *config.Config, client *feishu.Client, sessionMgr *session.Manager) *AuthHandler {
	return &AuthHandler{
		cfg:     cfg,
		client:  client,
		session: sessionMgr,
	}
}

func (h *AuthHandler) HandleLogin(c *gin.Context) {
	redirectURL := c.Query("redirect_uri")
	if redirectURL == "" {
		redirectURL = h.cfg.Server.BaseURL
	}

	state := feishu.EncodeState(redirectURL)

	oauthURL := feishu.BuildOAuthURL(
		h.cfg.Feishu.AppID,
		h.cfg.Server.CallbackURL,
		state,
	)

	log.Printf("[Auth] OAuth 登录请求: redirect_uri=%s, state=%s", redirectURL, state)

	c.Redirect(http.StatusTemporaryRedirect, oauthURL)
}

func (h *AuthHandler) HandleCallback(c *gin.Context) {
	code := c.Query("code")
	state := c.Query("state")

	if code == "" {
		log.Printf("[Auth] 回调缺少 code 参数")
		common.BadRequest(c, "缺少授权码")
		return
	}

	log.Printf("[Auth] OAuth 回调: code=%s..., state=%s", code[:common.Min(10, len(code))], state)

	tokenResp, err := h.client.GetUserAccessToken(code, h.cfg.Server.CallbackURL)
	if err != nil {
		log.Printf("[Auth] 获取 user_access_token 失败: %v", err)
		common.InternalError(c, "获取访问令牌失败")
		return
	}

	log.Printf("[Auth] 获取 user_access_token 成功: access_token=%s...",
		tokenResp.AccessToken[:common.Min(20, len(tokenResp.AccessToken))])

	userInfo, err := h.client.GetUserInfo(tokenResp.AccessToken)
	if err != nil {
		log.Printf("[Auth] 获取用户信息失败: %v", err)
		common.InternalError(c, "获取用户信息失败")
		return
	}

	userID := userInfo.Data.UserID
	unionID := userInfo.Data.UnionID

	log.Printf("[Auth] 用户信息: user_id=%s, union_id=%s, name=%s, mobile=%s",
		userID, unionID, userInfo.Data.Name, userInfo.Data.Mobile)

	sess, err := h.session.CreateSession(userID, unionID)
	if err != nil {
		log.Printf("[Auth] 创建会话失败: %v", err)
		common.InternalError(c, "创建会话失败")
		return
	}

	redirectURL, err := feishu.DecodeState(state)
	if err != nil {
		log.Printf("[Auth] 解码 state 失败: %v", err)
		redirectURL = h.cfg.Server.BaseURL
	}

	parsedURL, err := url.Parse(redirectURL)
	if err != nil {
		parsedURL, _ = url.Parse(h.cfg.Server.BaseURL)
	}

	query := parsedURL.Query()
	query.Set("token", sess.Token)
	parsedURL.RawQuery = query.Encode()

	finalURL := parsedURL.String()
	log.Printf("[Auth] 登录成功，重定向到: %s", finalURL)

	c.Redirect(http.StatusTemporaryRedirect, finalURL)
}
