package feishu

// ============ 飞书 API 基础配置 ============
const (
	FeishuAPIHost = "https://open.feishu.cn"
)

// ============ 飞书 API 端点常量 ============

// 认证相关
const (
	ApiGetToken = "/open-apis/auth/v3/tenant_access_token/internal"
)

// OAuth 相关
const (
	OAuthAuthorizeURL = "https://open.feishu.cn/open-apis/authen/v1/authorize"
	ApiOAuthToken      = "/open-apis/authen/v2/oauth/token"
	ApiUserInfo        = "/open-apis/authen/v1/user_info"
)

// 部门相关 (directory/v1)
const (
	ApiDepartmentFilter = "/open-apis/directory/v1/departments/filter"
)

// 用户相关 (contact/v3)
const (
	ApiUserFindByDepartment = "/open-apis/contact/v3/users/find_by_department"
)

// ============ 分页配置 ============
const (
	MaxPageSize = 50 // directory API 最大 100
)

// ============ 调试开关 ============
var (
	DebugRequest  = false // 打印请求参数
	DebugResponse = false // 打印响应结果
)
