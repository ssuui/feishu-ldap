package feishu

import (
	"encoding/json"
	"fmt"
	"testing"

	"feishu-ldap-server/config"
)

const configPath = "../../config/config.yaml"

func loadConfig(t *testing.T) *config.Config {
	cfg, err := config.LoadConfig(configPath)
	if err != nil {
		t.Fatalf("加载配置失败：%v", err)
	}

	if cfg.Feishu.AppID == "" || cfg.Feishu.AppSecret == "" {
		t.Skip("跳过测试：请在 config/config.yaml 中配置飞书凭证")
	}

	return cfg
}

func TestClient_GetToken(t *testing.T) {
	cfg := loadConfig(t)
	client := NewClient(cfg.Feishu.AppID, cfg.Feishu.AppSecret)

	token, err := client.GetToken()
	if err != nil {
		t.Fatalf("获取 token 失败：%v", err)
	}

	fmt.Printf("✅ Token: %s...\n", token[:20])
}

func TestDepartment_GetAllDepartments(t *testing.T) {
	cfg := loadConfig(t)
	client := NewClient(cfg.Feishu.AppID, cfg.Feishu.AppSecret)

	depts, err := client.GetAllDepartments()
	if err != nil {
		t.Fatalf("获取部门失败：%v", err)
	}

	fmt.Printf("✅ [新 API] 共获取 %d 个部门\n", len(depts))
	for i, dept := range depts {
		if i >= 10 {
			break
		}
		fmt.Printf("   - %s (ID: %s, 父部门：%s)\n", dept.GetName(), dept.DepartmentID, dept.ParentID)
	}
}

func TestDepartment_BuildTree(t *testing.T) {
	cfg := loadConfig(t)
	client := NewClient(cfg.Feishu.AppID, cfg.Feishu.AppSecret)

	depts, err := client.GetAllDepartments()
	if err != nil {
		t.Fatalf("获取部门失败：%v", err)
	}

	tree := BuildDepartmentTree(depts)

	jsonTree, _ := json.MarshalIndent(tree, "", "  ")
	fmt.Printf("[📋 构建的请求体]\n%s\n", string(jsonTree))

	fmt.Printf("✅ 部门树：共 %d 个根节点\n", len(tree["0"]))
}

// ============ 用户测试 ============

func TestUser_GetUsersByDepartment(t *testing.T) {
	cfg := loadConfig(t)
	client := NewClient(cfg.Feishu.AppID, cfg.Feishu.AppSecret)

	depts, err := client.GetAllDepartments()
	if err != nil {
		t.Fatalf("获取部门失败：%v", err)
	}

	if len(depts) == 0 {
		t.Skip("跳过测试：没有部门数据")
	}

	for _, dept := range depts {

		fmt.Printf("   - %s (%s)\n", dept.GetName(), dept.DepartmentID)
		users, err := client.GetAllUsersByDepartment(dept.DepartmentID)
		if err != nil {
			t.Fatalf("获取部门用户失败：%v", err)
		}

		fmt.Printf("✅ [find_by_department] 部门 [%s] 共获取 %d 个直属用户\n", dept.GetName(), len(users))
		for i, user := range users {
			if i >= 5 {
				break
			}
			fmt.Printf("   - %s (%s)\n", user.Name, user.Mobile)
		}
	}

}
