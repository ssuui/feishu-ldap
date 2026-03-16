package contact

import "github.com/pquerna/otp/totp"

// LDAPUser LDAP 用户数据结构
// 包含用户基本信息和 TOTP 秘钥
type LDAPUser struct {
	UserID     string `json:"user_id"`     // 飞书用户 ID
	UnionID    string `json:"union_id"`    // 飞书 Union ID
	Mobile     string `json:"mobile"`      // 手机号
	Email      string `json:"email"`       // 邮箱
	Name       string `json:"name"`        // 姓名
	DN         string `json:"dn"`          // LDAP DN，如 "uid=zhangsan,ou=tech,dc=example,dc=com"
	TOTPSecret string `json:"totp_secret"` // TOTP 秘钥（Base32 编码）

	// LDAP 标准属性
	ObjectClass []string `json:"object_class"` // 对象类
	CN          string   `json:"cn"`           // 通用名
	SN          string   `json:"sn"`           // 姓
	UID         string   `json:"uid"`          // 用户 ID
	OU          string   `json:"ou"`           // 组织单元
}

// LDAPDepartment LDAP 部门数据结构
type LDAPDepartment struct {
	DepartmentID string `json:"department_id"` // 飞书部门 ID
	Name         string `json:"name"`          // 部门名称
	ParentID     string `json:"parent_id"`     // 父部门 ID
	DN           string `json:"dn"`            // LDAP DN
	ParentDN     string `json:"parent_dn"`     // 父部门 DN

	// LDAP 标准属性
	ObjectClass []string `json:"object_class"` // 对象类
	OU          string   `json:"ou"`           // 组织单元名称
}

// ContactData 完整的通讯录数据
// 这是持久化到文件的数据结构
type ContactData struct {
	Version     int                        `json:"version"`     // 数据版本
	SyncTime    string                     `json:"sync_time"`   // 同步时间
	BaseDN      string                     `json:"base_dn"`     // 基础 DN
	Departments map[string]*LDAPDepartment `json:"departments"` // 部门 ID -> 部门
	Users       map[string]*LDAPUser       `json:"users"`       // 用户 ID -> 用户
	DeptTree    *DepartmentTreeNode        `json:"dept_tree"`   // 部门树
}

// DepartmentTreeNode 部门树节点
type DepartmentTreeNode struct {
	DepartmentID string                `json:"department_id"`
	Name         string                `json:"name"`
	DN           string                `json:"dn"`
	Children     []*DepartmentTreeNode `json:"children"`
	UserIDs      []string              `json:"user_ids"` // 该部门直属用户 ID 列表
}

// SyncResult 同步结果
type SyncResult struct {
	TotalDepartments int      `json:"total_departments"`
	TotalUsers       int      `json:"total_users"`
	NewUsers         int      `json:"new_users"`          // 新增用户数
	UpdatedUsers     int      `json:"updated_users"`      // 更新用户数
	NewTOTPGenerated int      `json:"new_totp_generated"` // 新生成 TOTP 的用户数
	SyncTime         string   `json:"sync_time"`
	Errors           []string `json:"errors,omitempty"`
}

// generateTOTPSecret 生成随机 TOTP 秘钥
func generateTOTPSecret() (string, error) {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "FeiShu-LDAP",
		AccountName: "user",
	})
	if err != nil {
		return "", err
	}
	return key.Secret(), nil
}
