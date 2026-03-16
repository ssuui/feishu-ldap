package ldap

import (
	"log"
	"strings"

	"github.com/pquerna/otp/totp"

	"feishu-ldap-server/internal/contact"
)

// TOTPPrefix TOTP 密码前缀
// 用户登录时需要输入：前缀 + 6位动态验证码
const TOTPPrefix = "totp_pwd_"

// AuthResult 认证结果
type AuthResult struct {
	Success   bool   // 是否认证成功
	Username  string // 用户名
	Reason    string // 失败原因
	IsService bool   // 是否为服务连接
}

// Authenticator 认证器
// 负责处理 LDAP Bind 请求的认证逻辑
type Authenticator struct {
	baseDN              string         // LDAP 基础 DN
	serviceBindDN       string         // 服务连接专用 DN
	serviceBindPassword string         // 服务连接专用密码
	cache               *contact.Cache // 通讯录缓存
}

// NewAuthenticator 创建认证器
func NewAuthenticator(baseDN, serviceBindDN, serviceBindPassword string) *Authenticator {
	return &Authenticator{
		baseDN:              baseDN,
		serviceBindDN:       serviceBindDN,
		serviceBindPassword: serviceBindPassword,
	}
}

// SetCache 设置缓存
func (a *Authenticator) SetCache(cache *contact.Cache) {
	a.cache = cache
}

// Authenticate 执行认证
// 这是认证的主入口，会根据 DN 判断是服务连接还是用户登录
// 参数:
//   - bindDN: 客户端提供的 DN，如 "cn=admin,dc=example,dc=com" 或 "uid=13800138000,ou=tech,dc=example,dc=com"
//   - password: 客户端提供的密码
//
// 返回: 认证结果
func (a *Authenticator) Authenticate(bindDN, password string) (*AuthResult, error) {
	// 判断是否为服务连接
	if a.isServiceBindDN(bindDN) {
		// Step 1: 第三方服务连接认证
		return a.authenticateService(bindDN, password)
	}

	// Step 3: 用户登录认证
	return a.authenticateUser(bindDN, password)
}

// isServiceBindDN 判断是否为服务连接 DN
func (a *Authenticator) isServiceBindDN(bindDN string) bool {
	// 标准化比较（忽略大小写和空格）
	normalizedInput := strings.ToLower(strings.TrimSpace(bindDN))
	normalizedService := strings.ToLower(strings.TrimSpace(a.serviceBindDN))

	return normalizedInput == normalizedService
}

// authenticateService 处理服务连接认证
// 这是 Step 1: 第三方服务通过固定账号密码连接到 LDAP 服务器
// 参数:
//   - bindDN: 服务连接 DN
//   - password: 服务连接密码
func (a *Authenticator) authenticateService(bindDN, password string) (*AuthResult, error) {
	// 验证密码是否匹配配置中的服务密码
	if password != a.serviceBindPassword {
		return &AuthResult{
			Success:   false,
			Username:  "service",
			Reason:    "Invalid service password",
			IsService: true,
		}, nil
	}

	// 认证成功
	return &AuthResult{
		Success:   true,
		Username:  "service",
		Reason:    "",
		IsService: true,
	}, nil
}

// authenticateUser 处理用户登录认证
// 这是 Step 3: 用户通过 TOTP 动态验证码登录
// 参数:
//   - bindDN: 用户 DN，如 "uid=13800138000,ou=tech,dc=example,dc=com"
//   - password: 用户密码，格式为 "totp_pwd_123456"
func (a *Authenticator) authenticateUser(bindDN, password string) (*AuthResult, error) {
	// 检查缓存是否初始化
	if a.cache == nil {
		return &AuthResult{
			Success:  false,
			Username: "",
			Reason:   "Cache not initialized",
		}, nil
	}

	// 从 DN 中提取用户 UID
	uid := extractUIDFromDN(bindDN)
	if uid == "" {
		return &AuthResult{
			Success:  false,
			Username: "",
			Reason:   "Invalid user DN format",
		}, nil
	}

	// 从缓存中查找用户
	user := a.cache.GetUserByUID(uid)
	if user == nil {
		// 尝试通过手机号查找
		user = a.cache.GetUserByMobile(uid)
	}

	if user == nil {
		log.Printf("[Auth] User not found: %s (uid=%s)", bindDN, uid)
		return &AuthResult{
			Success:  false,
			Username: uid,
			Reason:   "User not found",
		}, nil
	}

	// 验证密码格式（必须包含 TOTP 前缀）
	if !strings.HasPrefix(password, TOTPPrefix) {
		log.Printf("[Auth] Invalid password format for user %s (missing TOTP prefix)", user.Name)
		return &AuthResult{
			Success:  false,
			Username: user.Name,
			Reason:   "Invalid password format, TOTP required",
		}, nil
	}

	// 提取 TOTP 验证码
	totpCode := strings.TrimPrefix(password, TOTPPrefix)

	// 验证 TOTP
	if user.TOTPSecret == "" {
		log.Printf("[Auth] User %s has no TOTP secret", user.Name)
		return &AuthResult{
			Success:  false,
			Username: user.Name,
			Reason:   "User TOTP not configured",
		}, nil
	}

	// 使用 TOTP 库验证验证码
	valid := totp.Validate(totpCode, user.TOTPSecret)
	if !valid {
		log.Printf("[Auth] Invalid TOTP code for user %s", user.Name)
		return &AuthResult{
			Success:  false,
			Username: user.Name,
			Reason:   "Invalid TOTP code",
		}, nil
	}

	// 认证成功
	log.Printf("[Auth] User %s authenticated successfully via TOTP", user.Name)
	return &AuthResult{
		Success:  true,
		Username: user.Name,
		Reason:   "",
	}, nil
}

// extractUIDFromDN 从 DN 中提取 UID
// 例如：从 "uid=13800138000,ou=tech,dc=example,dc=com" 中提取 "13800138000"
func extractUIDFromDN(dn string) string {
	// DN 格式：uid=xxx,ou=yyy,dc=zzz
	// 我们需要提取 uid= 后面的值

	dn = strings.TrimSpace(dn)
	if !strings.HasPrefix(strings.ToLower(dn), "uid=") {
		return ""
	}

	// 找到第一个逗号的位置
	commaIndex := strings.Index(dn, ",")
	if commaIndex == -1 {
		// 没有逗号，整个 DN 就是 uid=xxx
		return dn[4:]
	}

	// 提取 uid 值
	return dn[4:commaIndex]
}
