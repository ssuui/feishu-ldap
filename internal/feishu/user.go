package feishu

import (
	"fmt"
	"net/url"
)

// User 飞书用户信息（仅保留需要的字段）
type User struct {
	UserID  string `json:"user_id"`
	UnionID string `json:"union_id"`
	Mobile  string `json:"mobile"`
	Email   string `json:"email"`
	Name    string `json:"name"`
}

// UserListResponse 用户列表响应
type UserListResponse struct {
	Code int      `json:"code"`
	Msg  string   `json:"msg"`
	Data UserData `json:"data"`
}

// UserData 用户数据
type UserData struct {
	Items     []User `json:"items"`
	HasMore   bool   `json:"has_more"`
	PageToken string `json:"page_token"`
	Total     int    `json:"total"`
}

// GetUsersByDepartment 获取指定部门下的直属用户列表（支持分页）
// 使用飞书推荐 API: GET /open-apis/contact/v3/users/find_by_department
func (c *Client) GetUsersByDepartment(departmentID string, pageSize int, pageToken string) (*UserListResponse, error) {
	if departmentID == "" {
		return nil, fmt.Errorf("部门 ID 不能为空")
	}

	if pageSize > MaxPageSize {
		pageSize = MaxPageSize
	}
	if pageSize <= 0 {
		pageSize = MaxPageSize
	}

	query := url.Values{}
	query.Set("user_id_type", "union_id")
	query.Set("department_id_type", "department_id")
	query.Set("department_id", departmentID)
	query.Set("page_size", fmt.Sprintf("%d", pageSize))

	if pageToken != "" {
		query.Set("page_token", pageToken)
	}

	endpoint := ApiUserFindByDepartment + "?" + query.Encode()

	var result UserListResponse
	err := c.request("GET", endpoint, nil, &result)
	if err != nil {
		return nil, err
	}

	if result.Code != 0 {
		return nil, fmt.Errorf("API 错误 [%d]: %s", result.Code, result.Msg)
	}

	return &result, nil
}

// GetAllUsersByDepartment 获取指定部门下的全部用户（自动分页）
func (c *Client) GetAllUsersByDepartment(departmentID string) ([]User, error) {
	var allUsers []User
	var pageToken string

	for {
		resp, err := c.GetUsersByDepartment(departmentID, MaxPageSize, pageToken)
		if err != nil {
			return nil, fmt.Errorf("获取部门用户失败：%w", err)
		}

		allUsers = append(allUsers, resp.Data.Items...)

		if !resp.Data.HasMore {
			break
		}

		pageToken = resp.Data.PageToken
	}

	return allUsers, nil
}

// GetAllUsers 获取全部用户（全量，自动分页）
func (c *Client) GetAllUsers() ([]User, error) {
	var allUsers []User
	var pageToken string

	for {
		query := url.Values{}
		query.Set("page_size", fmt.Sprintf("%d", MaxPageSize))

		if pageToken != "" {
			query.Set("page_token", pageToken)
		}

		endpoint := "/open-apis/contact/v3/users?" + query.Encode()

		var result UserListResponse
		err := c.request("GET", endpoint, nil, &result)
		if err != nil {
			return nil, fmt.Errorf("获取用户失败：%w", err)
		}

		if result.Code != 0 {
			return nil, fmt.Errorf("API 错误 [%d]: %s", result.Code, result.Msg)
		}

		allUsers = append(allUsers, result.Data.Items...)

		if !result.Data.HasMore {
			break
		}

		pageToken = result.Data.PageToken
	}

	return allUsers, nil
}

// DeduplicateUsers 用户去重（基于 UserID）
func DeduplicateUsers(users []User) []User {
	userMap := make(map[string]User)
	for _, user := range users {
		userMap[user.UserID] = user
	}

	var uniqueUsers []User
	for _, user := range userMap {
		uniqueUsers = append(uniqueUsers, user)
	}

	return uniqueUsers
}
