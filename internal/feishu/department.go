package feishu

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Department 部门
type Department struct {
	DepartmentID    string         `json:"department_id"`
	Name            DepartmentName `json:"name"`
	ParentID        string         `json:"parent_department_id,omitempty"`
	DepartmentCode  string         `json:"department_code,omitempty"`
	Order           int            `json:"order,omitempty"`
	DepartmentCount map[string]int `json:"department_count,omitempty"`
}

// DepartmentName 部门名称（支持多语言）
type DepartmentName struct {
	DefaultValue string `json:"default_value"`
}

// GetName 获取部门名称
func (d *Department) GetName() string {
	if d.Name.DefaultValue != "" {
		return d.Name.DefaultValue
	}
	return ""
}

// FilterCondition 筛选条件
type FilterCondition struct {
	Field    string `json:"field"`
	Operator string `json:"operator"`
	Value    string `json:"value"`
}

// Filter 筛选器
type Filter struct {
	Conditions []FilterCondition `json:"conditions"`
}

// PageRequest 分页请求
type PageRequest struct {
	PageSize  int    `json:"page_size"`
	PageToken string `json:"page_token"`
}

// DepartmentFilterRequest 部门筛选请求
type DepartmentFilterRequest struct {
	Filter         *Filter     `json:"filter"`
	RequiredFields []string    `json:"required_fields,omitempty"`
	PageRequest    PageRequest `json:"page_request"`
}

// PageResponse 分页响应
type PageResponse struct {
	HasMore   bool   `json:"has_more"`
	PageToken string `json:"page_token"`
}

// DepartmentFilterResponseData 响应数据
type DepartmentFilterResponseData struct {
	Departments  []Department `json:"departments"`
	PageResponse PageResponse `json:"page_response"`
}

// DepartmentFilterResponse 部门筛选响应
type DepartmentFilterResponse struct {
	Code int                          `json:"code"`
	Msg  string                       `json:"msg"`
	Data DepartmentFilterResponseData `json:"data"`
}

// buildFilterRequest 构建带筛选条件的请求体
func buildFilterRequest(parentID string, pageSize int, pageToken string) DepartmentFilterRequest {
	conditions := make([]FilterCondition, 0, 1)
	conditions = append(conditions, FilterCondition{
		Field:    "parent_department_id",
		Operator: "eq",
		Value:    fmt.Sprintf("\"%s\"", parentID),
	})

	filter := &Filter{
		Conditions: conditions,
	}

	return DepartmentFilterRequest{
		Filter:         filter,
		RequiredFields: []string{"name", "parent_department_id", "department_id"},
		PageRequest: PageRequest{
			PageSize:  pageSize,
			PageToken: pageToken,
		},
	}
}

// GetDepartmentsByParent 根据父部门 ID 获取子部门列表（单页）
func (c *Client) GetDepartmentsByParent(parentID string, pageSize int, pageToken string) (*DepartmentFilterResponse, error) {
	if pageSize > MaxPageSize {
		pageSize = MaxPageSize
	}
	if pageSize <= 0 {
		pageSize = MaxPageSize
	}

	if parentID == "" {
		parentID = "0"
	}

	fmt.Printf("\n[🏢 获取子部门] 父部门 ID=%s | pageSize=%d, pageToken=%q\n",
		parentID, pageSize, pageToken)

	reqBody := buildFilterRequest(parentID, pageSize, pageToken)

	if DebugRequest {
		jsonBytes, err := json.MarshalIndent(reqBody, "", "  ")
		if err != nil {
			fmt.Printf("⚠️  请求体序列化失败：%v\n", err)
		} else {
			fmt.Printf("[📋 构建的请求体]\n%s\n", string(jsonBytes))
		}
	}

	var result DepartmentFilterResponse
	err := c.request(
		"POST",
		ApiDepartmentFilter+"?department_id_type=department_id&employee_id_type=union_id",
		reqBody,
		&result)
	if err != nil {
		return nil, err
	}

	if result.Code != 0 {
		return nil, fmt.Errorf("API 错误 [%d]: %s", result.Code, result.Msg)
	}

	fmt.Printf("[✅ API 响应] 返回 %d 个部门, hasMore=%v, pageToken=%q\n",
		len(result.Data.Departments), result.Data.PageResponse.HasMore, result.Data.PageResponse.PageToken)

	return &result, nil
}

// GetAllDepartmentsByParent 获取指定父部门下的全部子部门（自动分页）
func (c *Client) GetAllDepartmentsByParent(parentID string) ([]Department, error) {
	if parentID == "" {
		parentID = "0"
	}

	fmt.Printf("\n[📄 获取全部子部门] 父部门 ID=%s\n", parentID)
	fmt.Println(strings.Repeat("-", 60))

	var allDepts []Department
	var pageToken string
	var pageCount int
	const maxPages = 50 // 安全限制：最多 50 页

	// 用于检测 pageToken 是否重复（防止无限循环）
	seenTokens := make(map[string]bool)

	for {
		pageCount++

		// 安全检查 1: 超过最大页数
		if pageCount > maxPages {
			fmt.Printf("⚠️  [安全限制] 已达到最大页数 %d，停止分页\n", maxPages)
			break
		}

		// 安全检查 2: pageToken 重复
		if pageToken != "" && seenTokens[pageToken] {
			fmt.Printf("⚠️  [安全限制] pageToken 重复：%q，停止分页\n", pageToken)
			break
		}
		seenTokens[pageToken] = true

		fmt.Printf("  [📄 第 %d 页] pageToken=%q\n", pageCount, pageToken)

		resp, err := c.GetDepartmentsByParent(parentID, MaxPageSize, pageToken)
		if err != nil {
			return nil, fmt.Errorf("获取部门失败：%w", err)
		}

		// 安全检查 3: 返回空数组但 hasMore=true
		if len(resp.Data.Departments) == 0 && resp.Data.PageResponse.HasMore {
			fmt.Printf("⚠️  [安全警告] 返回空数组但 hasMore=true，停止分页\n")
			break
		}

		allDepts = append(allDepts, resp.Data.Departments...)
		fmt.Printf("  [📊 累计] 当前页 %d 个，累计 %d 个部门\n",
			len(resp.Data.Departments), len(allDepts))

		// 没有更多数据，退出循环
		if !resp.Data.PageResponse.HasMore {
			fmt.Printf("  [✅ 分页完成] 共 %d 页，%d 个部门\n", pageCount, len(allDepts))
			break
		}

		// 更新 pageToken
		pageToken = resp.Data.PageResponse.PageToken

		// 安全检查 4: pageToken 为空但 hasMore=true
		if pageToken == "" && resp.Data.PageResponse.HasMore {
			fmt.Printf("⚠️  [安全警告] hasMore=true 但 pageToken 为空，停止分页\n")
			break
		}
	}

	fmt.Println(strings.Repeat("-", 60))
	return allDepts, nil
}

// GetAllDepartments 获取全部部门（递归获取所有层级）
func (c *Client) GetAllDepartments() ([]Department, error) {
	fmt.Printf("\n[🔄 开始获取全部部门（递归）]\n")
	fmt.Println(strings.Repeat("=", 80))

	var allDepts []Department

	// 步骤 1: 获取一级部门（parent_department_id = "0"）
	fmt.Printf("\n[🌱 步骤 1] 获取一级部门...\n")
	// 重要：这里获取的是 parent_department_id="0" 的部门（一级部门）
	// 注意：根部门（ID="0"）不会被包含在返回中
	deptList, err := c.GetAllDepartmentsByParent("0")
	if err != nil {
		return nil, fmt.Errorf("获取一级部门失败：%w", err)
	}

	// 关键修复：不过滤任何部门！
	// 一级部门的 ID ≠ "0"，所以直接使用
	allDepts = append(allDepts, deptList...)

	fmt.Printf("[🌱 一级部门完成] 获取 %d 个一级部门（parent_department_id=\"0\"）\n", len(deptList))

	// 如果没有一级部门，直接返回
	if len(deptList) == 0 {
		fmt.Printf("[⚠️  警告] 没有获取到一级部门\n")
		return allDepts, nil
	}

	// 步骤 2: 递归获取每个一级部门的子部门
	fmt.Printf("\n[🌳 步骤 2] 递归获取子部门...\n")
	for _, dept := range deptList {
		fmt.Printf("\n[🔍 递归] 开始获取 [%s] (%s) 的子部门...\n", dept.GetName(), dept.DepartmentID)

		subDepts, err := c.getAllSubDepartments(dept.DepartmentID, 1)
		if err != nil {
			fmt.Printf("⚠️  获取部门 [%s] 的子部门失败：%v\n", dept.GetName(), err)
			continue
		}

		allDepts = append(allDepts, subDepts...)
		fmt.Printf("[✅ 递归完成] [%s] 共获取 %d 个子部门\n", dept.GetName(), len(subDepts))
	}

	fmt.Printf("\n[✅ 获取全部部门完成] 共 %d 个部门\n", len(allDepts))
	fmt.Println(strings.Repeat("=", 80))

	return allDepts, nil
}

// getAllSubDepartments 递归获取子部门（内部方法）
func (c *Client) getAllSubDepartments(parentID string, level int) ([]Department, error) {
	var allSubDepts []Department

	// 构建缩进用于打印
	indent := strings.Repeat("  ", level)

	// 安全检查：确保父部门ID不是"0"（根部门ID）
	if parentID == "0" {
		fmt.Printf("%s[⚠️ 跳过] 父部门ID为0（根部门），跳过递归\n", indent)
		return allSubDepts, nil
	}

	fmt.Printf("%s[🔍 层级 %d] 获取父部门 [%s] 的子部门...\n", indent, level, parentID)

	// 获取当前层级的全部子部门（自动分页）
	subDepts, err := c.GetAllDepartmentsByParent(parentID)
	if err != nil {
		return nil, err
	}

	fmt.Printf("%s[📊 结果] 获取到 %d 个子部门\n", indent, len(subDepts))

	// 如果没有子部门，直接返回（递归终止条件）
	if len(subDepts) == 0 {
		fmt.Printf("%s[✅ 终止] 没有子部门，停止递归\n", indent)
		return allSubDepts, nil
	}

	allSubDepts = append(allSubDepts, subDepts...)

	// 打印当前层级
	for _, dept := range subDepts {
		fmt.Printf("%s  └─ [%s] %s\n", indent, dept.DepartmentID, dept.GetName())
	}

	// 递归获取下一层级
	fmt.Printf("%s[🔄 继续] 递归获取 %d 个子部门的下一级...\n", indent, len(subDepts))
	for _, dept := range subDepts {
		deeperSubDepts, err := c.getAllSubDepartments(dept.DepartmentID, level+1)
		if err != nil {
			fmt.Printf("%s⚠️  获取部门 [%s] 的子部门失败：%v\n", indent, dept.GetName(), err)
			continue
		}
		allSubDepts = append(allSubDepts, deeperSubDepts...)
	}

	return allSubDepts, nil
}

// BuildDepartmentTree 构建部门树
func BuildDepartmentTree(departments []Department) map[string][]Department {
	tree := make(map[string][]Department)

	for _, dept := range departments {
		parentID := dept.ParentID
		if parentID == "" {
			parentID = "0"
		}
		tree[parentID] = append(tree[parentID], dept)
	}

	return tree
}

func __() {
	fmt.Println("getFunc")
}
