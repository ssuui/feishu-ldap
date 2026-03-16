package contact

import (
	"fmt"
	"log"
	"strings"
	"time"

	"feishu-ldap-server/internal/feishu"
)

// Syncer 通讯录同步器
type Syncer struct {
	client *feishu.Client // 飞书 API 客户端
	cache  *Cache         // 内存缓存
	baseDN string         // LDAP 基础 DN
}

// NewSyncer 创建同步器
func NewSyncer(client *feishu.Client, cache *Cache, baseDN string) *Syncer {
	return &Syncer{
		client: client,
		cache:  cache,
		baseDN: baseDN,
	}
}

// Sync 执行完整同步
// 1. 获取所有部门
// 2. 构建 LDAP 部门结构
// 3. 获取所有用户
// 4. 为用户生成 TOTP 秘钥
// 5. 保存到内存和文件
func (s *Syncer) Sync() (*SyncResult, error) {
	log.Println("[Sync] 开始同步通讯录...")
	startTime := time.Now()

	result := &SyncResult{
		SyncTime: startTime.Format(time.RFC3339),
	}

	// 获取旧数据用于比较
	oldData := s.cache.GetData()
	oldUsers := make(map[string]*LDAPUser)
	if oldData != nil {
		for k, v := range oldData.Users {
			oldUsers[k] = v
		}
	}

	// Step 1: 获取所有部门
	log.Println("[Sync] Step 1: 获取部门列表...")
	departments, err := s.client.GetAllDepartments()
	if err != nil {
		return nil, fmt.Errorf("获取部门失败: %w", err)
	}
	result.TotalDepartments = len(departments)
	log.Printf("[Sync] 获取到 %d 个部门", len(departments))

	// Step 2: 构建 LDAP 部门结构
	log.Println("[Sync] Step 2: 构建 LDAP 部门结构...")
	ldapDepts, deptTree := s.buildLDAPDepartments(departments)

	// Step 3: 获取所有用户
	log.Println("[Sync] Step 3: 获取用户列表...")
	allUsers, userDeptMap, err := s.fetchAllUsers(departments)
	if err != nil {
		return nil, fmt.Errorf("获取用户失败: %w", err)
	}

	// 去重
	uniqueUsers := feishu.DeduplicateUsers(allUsers)
	result.TotalUsers = len(uniqueUsers)
	log.Printf("[Sync] 获取到 %d 个用户（去重后）", len(uniqueUsers))

	// Step 4: 构建 LDAP 用户结构并生成 TOTP
	log.Println("[Sync] Step 4: 构建 LDAP 用户结构并生成 TOTP 秘钥...")
	ldapUsers := s.buildLDAPUsers(uniqueUsers, ldapDepts, userDeptMap, oldUsers, result)

	// Step 5: 保存数据
	log.Println("[Sync] Step 5: 保存数据...")
	contactData := &ContactData{
		Version:     1,
		SyncTime:    startTime.Format(time.RFC3339),
		BaseDN:      s.baseDN,
		Departments: ldapDepts,
		Users:       ldapUsers,
		DeptTree:    deptTree,
	}

	if err := s.cache.Save(contactData); err != nil {
		return nil, fmt.Errorf("保存数据失败: %w", err)
	}

	elapsed := time.Since(startTime)
	log.Printf("[Sync] 同步完成！耗时: %v", elapsed)
	log.Printf("[Sync] 统计: 部门=%d, 用户=%d, 新增=%d, 更新=%d, 新TOTP=%d",
		result.TotalDepartments, result.TotalUsers,
		result.NewUsers, result.UpdatedUsers, result.NewTOTPGenerated)

	return result, nil
}

// buildLDAPDepartments 构建 LDAP 部门结构
func (s *Syncer) buildLDAPDepartments(departments []feishu.Department) (map[string]*LDAPDepartment, *DepartmentTreeNode) {
	ldapDepts := make(map[string]*LDAPDepartment)

	// 第一遍：创建所有部门
	for _, dept := range departments {
		ldapDept := &LDAPDepartment{
			DepartmentID: dept.DepartmentID,
			Name:         dept.GetName(),
			ParentID:     dept.ParentID,
			ObjectClass:  []string{"top", "organizationalUnit"},
			OU:           dept.GetName(),
		}
		ldapDepts[dept.DepartmentID] = ldapDept
	}

	// 第二遍：构建 DN（使用递归确保父部门 DN 先构建）
	for _, ldapDept := range ldapDepts {
		ldapDept.DN = s.buildDepartmentDNRecursive(ldapDept, ldapDepts, make(map[string]bool))
		if ldapDept.ParentID != "" && ldapDept.ParentID != "0" {
			if parent, ok := ldapDepts[ldapDept.ParentID]; ok {
				ldapDept.ParentDN = parent.DN
			}
		}
	}

	// 构建部门树
	deptTree := s.buildDepartmentTree(ldapDepts)

	return ldapDepts, deptTree
}

// buildDepartmentDNRecursive 递归构建部门 DN（确保父部门 DN 先构建）
func (s *Syncer) buildDepartmentDNRecursive(dept *LDAPDepartment, allDepts map[string]*LDAPDepartment, visited map[string]bool) string {
	// 防止循环引用
	if visited[dept.DepartmentID] {
		return fmt.Sprintf("ou=%s,%s", sanitizeDN(dept.Name), s.baseDN)
	}
	visited[dept.DepartmentID] = true

	// 如果 DN 已经构建过，直接返回
	if dept.DN != "" {
		return dept.DN
	}

	ouName := sanitizeDN(dept.Name)

	// 一级部门（ParentID 为空或 "0"）
	if dept.ParentID == "" || dept.ParentID == "0" {
		return fmt.Sprintf("ou=%s,%s", ouName, s.baseDN)
	}

	// 有父部门，递归构建父部门 DN
	if parent, ok := allDepts[dept.ParentID]; ok {
		parentDN := s.buildDepartmentDNRecursive(parent, allDepts, visited)
		return fmt.Sprintf("ou=%s,%s", ouName, parentDN)
	}

	// 父部门不存在，直接挂在 BaseDN 下
	return fmt.Sprintf("ou=%s,%s", ouName, s.baseDN)
}

// buildDepartmentTree 构建部门树结构
func (s *Syncer) buildDepartmentTree(depts map[string]*LDAPDepartment) *DepartmentTreeNode {
	// 创建根节点（BaseDN）
	root := &DepartmentTreeNode{
		DepartmentID: "0",
		Name:         "Root",
		DN:           s.baseDN,
		Children:     []*DepartmentTreeNode{},
		UserIDs:      []string{},
	}

	// 找出所有一级部门（ParentID = "0" 或空）
	for _, dept := range depts {
		if dept.ParentID == "" || dept.ParentID == "0" {
			node := s.buildDepartmentTreeNode(dept, depts)
			root.Children = append(root.Children, node)
		}
	}

	return root
}

// buildDepartmentTreeNode 递归构建部门树节点
func (s *Syncer) buildDepartmentTreeNode(dept *LDAPDepartment, allDepts map[string]*LDAPDepartment) *DepartmentTreeNode {
	node := &DepartmentTreeNode{
		DepartmentID: dept.DepartmentID,
		Name:         dept.Name,
		DN:           dept.DN,
		Children:     []*DepartmentTreeNode{},
		UserIDs:      []string{},
	}

	// 找出所有子部门
	for _, child := range allDepts {
		if child.ParentID == dept.DepartmentID {
			childNode := s.buildDepartmentTreeNode(child, allDepts)
			node.Children = append(node.Children, childNode)
		}
	}

	return node
}

// fetchAllUsers 获取所有部门的用户，并记录用户所属部门
func (s *Syncer) fetchAllUsers(departments []feishu.Department) ([]feishu.User, map[string]string, error) {
	var allUsers []feishu.User
	userDeptMap := make(map[string]string) // userID -> departmentID

	for _, dept := range departments {
		log.Printf("[Sync] 获取部门 [%s] 的用户...", dept.GetName())

		users, err := s.client.GetAllUsersByDepartment(dept.DepartmentID)
		if err != nil {
			log.Printf("[Sync] 警告: 获取部门 [%s] 用户失败: %v", dept.GetName(), err)
			continue
		}

		// 记录用户所属部门
		for _, user := range users {
			userDeptMap[user.UserID] = dept.DepartmentID
		}

		allUsers = append(allUsers, users...)
		log.Printf("[Sync] 部门 [%s] 获取到 %d 个用户", dept.GetName(), len(users))
	}

	return allUsers, userDeptMap, nil
}

// buildLDAPUsers 构建 LDAP 用户结构
func (s *Syncer) buildLDAPUsers(users []feishu.User, depts map[string]*LDAPDepartment, userDeptMap map[string]string, oldUsers map[string]*LDAPUser, result *SyncResult) map[string]*LDAPUser {
	ldapUsers := make(map[string]*LDAPUser)

	for _, user := range users {
		uid := s.determineUID(user)

		// 根据用户所属部门 ID 获取部门 DN
		var userOU string
		if deptID, ok := userDeptMap[user.UserID]; ok {
			if dept, exists := depts[deptID]; exists {
				userOU = dept.DN
			}
		}

		// 如果没有找到部门，使用 BaseDN
		if userOU == "" {
			userOU = s.baseDN
		}

		// 构建 DN
		dn := fmt.Sprintf("uid=%s,%s", sanitizeDN(uid), userOU)

		// 处理 TOTP 秘钥
		var totpSecret string
		oldUser, exists := oldUsers[user.UserID]
		if exists && oldUser.TOTPSecret != "" {
			// 保留已有的 TOTP 秘钥
			totpSecret = oldUser.TOTPSecret
			result.UpdatedUsers++
		} else {
			// 生成新的 TOTP 秘钥
			secret, err := generateTOTPSecret()
			if err != nil {
				log.Printf("[Sync] 警告: 为用户 %s 生成 TOTP 秘钥失败: %v", user.Name, err)
				result.Errors = append(result.Errors, fmt.Sprintf("用户 %s TOTP 生成失败", user.Name))
				continue
			}
			totpSecret = secret
			result.NewTOTPGenerated++
			if !exists {
				result.NewUsers++
			}
		}

		ldapUser := &LDAPUser{
			UserID:      user.UserID,
			UnionID:     user.UnionID,
			Mobile:      normalizeMobile(user.Mobile),
			Email:       user.Email,
			Name:        user.Name,
			DN:          dn,
			TOTPSecret:  totpSecret,
			ObjectClass: []string{"top", "person", "organizationalPerson", "inetOrgPerson"},
			CN:          user.Name,
			SN:          extractSurname(user.Name),
			UID:         uid,
			OU:          userOU,
		}

		ldapUsers[user.UserID] = ldapUser
	}

	return ldapUsers
}

// determineUID 确定用户的 UID
func (s *Syncer) determineUID(user feishu.User) string {
	// 优先使用手机号
	if user.Mobile != "" {
		return normalizeMobile(user.Mobile)
	}

	// 其次使用邮箱前缀
	if user.Email != "" {
		parts := strings.Split(user.Email, "@")
		if len(parts) > 0 && parts[0] != "" {
			return parts[0]
		}
	}

	// 最后使用 UserID
	return user.UserID
}

// normalizeMobile 标准化手机号
// 去除 + 符号和国际区号，只保留纯手机号
func normalizeMobile(mobile string) string {
	// 去除所有空格和 -
	mobile = strings.ReplaceAll(mobile, " ", "")
	mobile = strings.ReplaceAll(mobile, "-", "")

	// 去除 + 号
	mobile = strings.TrimPrefix(mobile, "+")

	// 常见国际区号处理
	// 中国 +86，后面是 11 位手机号
	if strings.HasPrefix(mobile, "86") && len(mobile) == 13 {
		mobile = mobile[2:]
	}

	return mobile
}

// sanitizeDN 清理 DN 中的特殊字符
func sanitizeDN(name string) string {
	// LDAP DN 中的特殊字符需要转义
	replacer := strings.NewReplacer(
		"\\", "\\5c",
		",", "\\2c",
		"+", "\\2b",
		"<", "\\3c",
		">", "\\3e",
		";", "\\3b",
		"\"", "\\22",
		"=", "\\3d",
	)
	return replacer.Replace(name)
}

// extractSurname 从姓名中提取姓
func extractSurname(name string) string {
	if len(name) == 0 {
		return name
	}

	// 中文名通常第一个字是姓
	runes := []rune(name)
	if len(runes) > 0 {
		return string(runes[0])
	}

	return name
}
