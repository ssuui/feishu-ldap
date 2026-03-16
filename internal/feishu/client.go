package feishu

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"feishu-ldap-server/internal/common"
)

// Client 飞书 API 客户端
type Client struct {
	appID      string
	appSecret  string
	token      string
	tokenTime  time.Time
	mu         sync.RWMutex
	httpClient *http.Client
}

// NewClient 创建飞书客户端
func NewClient(appID, appSecret string) *Client {
	return &Client{
		appID:      appID,
		appSecret:  appSecret,
		httpClient: &http.Client{Timeout: 60 * time.Second},
	}
}

func (c *Client) GetToken() (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Token 有效期 2 小时，提前 10 分钟刷新
	if c.token != "" && time.Since(c.tokenTime) < 1*time.Hour {
		if DebugRequest {
			fmt.Printf("[💡 使用缓存 Token] 剩余有效期：%v\n",
				time.Hour-time.Since(c.tokenTime))
		}
		return c.token, nil
	}

	// 构建请求体
	reqBody := map[string]string{
		"app_id":     c.appID,
		"app_secret": c.appSecret,
	}

	// 序列化请求体
	reqBodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return "", fmt.Errorf("序列化请求体失败：%w", err)
	}

	// 构建完整 URL
	url := FeishuAPIHost + ApiGetToken

	// 创建请求
	req, err := http.NewRequest("POST", url, bytes.NewReader(reqBodyBytes))
	if err != nil {
		return "", fmt.Errorf("创建请求失败：%w", err)
	}

	// 设置请求头
	req.Header.Set("Content-Type", "application/json")

	// 打印请求信息
	if DebugRequest {
		fmt.Printf("\n[🔐 Token 请求] POST %s\n", url)
		var prettyJSON bytes.Buffer
		if err := json.Indent(&prettyJSON, reqBodyBytes, "", "  "); err == nil {
			fmt.Printf("请求体:\n%s\n", prettyJSON.String())
		}
		fmt.Println(strings.Repeat("-", 80))
	}

	// 发送请求
	startTime := time.Now()
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("发送请求失败：%w", err)
	}
	defer resp.Body.Close()

	// 读取响应
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("读取响应失败：%w", err)
	}

	elapsed := time.Since(startTime)

	// 打印响应信息
	if DebugResponse {
		fmt.Printf("[📥 Token 响应] 状态码：%d | 耗时：%v\n", resp.StatusCode, elapsed)
		var prettyJSON bytes.Buffer
		if err := json.Indent(&prettyJSON, respBody, "", "  "); err == nil {
			fmt.Printf("响应体:\n%s\n", prettyJSON.String())
		}
		fmt.Println(strings.Repeat("=", 80))
	}

	// 检查 HTTP 状态码
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("HTTP 错误：%d - %s", resp.StatusCode, string(respBody))
	}

	// 解析响应
	var result struct {
		Code              int    `json:"code"`
		Msg               string `json:"msg"`
		TenantAccessToken string `json:"tenant_access_token"`
		Expire            int    `json:"expire"`
	}

	if err := json.Unmarshal(respBody, &result); err != nil {
		return "", fmt.Errorf("反序列化响应失败：%w", err)
	}

	if result.Code != 0 {
		return "", fmt.Errorf("获取 token 失败 [%d]: %s", result.Code, result.Msg)
	}

	// 缓存 token
	c.token = result.TenantAccessToken
	c.tokenTime = time.Now()

	if DebugResponse {
		fmt.Printf("[✅ Token 获取成功] token: %s... (有效期 %d 秒)\n\n",
			c.token[:common.Min(20, len(c.token))], result.Expire)
	}

	return c.token, nil
}

// request 通用请求方法（带详细打印）
// 注意：此方法会自动获取 token 并添加到请求头
func (c *Client) request(method, endpoint string, body interface{}, result interface{}) error {
	// 获取 token（认证接口除外）
	var token string
	var err error

	if endpoint == ApiGetToken {
		// 如果是获取 token 接口，使用当前缓存的 token（如果有）
		c.mu.RLock()
		token = c.token
		c.mu.RUnlock()
	} else {
		// 其他接口需要先获取有效 token
		token, err = c.GetToken()
		if err != nil {
			return fmt.Errorf("获取 token 失败：%w", err)
		}
	}

	// 构建完整 URL
	url := FeishuAPIHost + endpoint

	// 序列化请求体
	var reqBody io.Reader
	var reqBodyBytes []byte
	if body != nil {
		var err error
		reqBodyBytes, err = json.Marshal(body)
		if err != nil {
			return fmt.Errorf("序列化请求体失败：%w", err)
		}
		reqBody = bytes.NewReader(reqBodyBytes)
	}

	// 创建请求
	req, err := http.NewRequest(method, url, reqBody)
	if err != nil {
		return fmt.Errorf("创建请求失败：%w", err)
	}

	// 设置请求头
	req.Header.Set("Content-Type", "application/json")

	// 添加 Authorization 头（如果有 token）
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	// 打印完整请求信息
	if DebugRequest {
		fmt.Printf("\n[📤 HTTP 请求] %s %s\n", method, url)
		fmt.Printf("请求头:\n")
		for k, v := range req.Header {
			if k == "Authorization" {
				if len(v[0]) > 20 {
					fmt.Printf("  %s: Bearer %s...\n", k, v[0][:20])
				} else {
					fmt.Printf("  %s: Bearer %s\n", k, v[0])
				}
			} else {
				fmt.Printf("  %s: %v\n", k, v)
			}
		}
		if len(reqBodyBytes) > 0 {
			var prettyJSON bytes.Buffer
			if err := json.Indent(&prettyJSON, reqBodyBytes, "", "  "); err == nil {
				fmt.Printf("请求体:\n%s\n", prettyJSON.String())
			} else {
				fmt.Printf("请求体:\n%s\n", string(reqBodyBytes))
			}
		} else {
			fmt.Printf("请求体: (无)\n")
		}
		fmt.Println(strings.Repeat("-", 80))
	}

	// 发送请求
	startTime := time.Now()
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("发送请求失败：%w", err)
	}
	defer resp.Body.Close()

	// 读取响应
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("读取响应失败：%w", err)
	}

	elapsed := time.Since(startTime)

	// 打印完整响应信息
	if DebugResponse {
		fmt.Printf("\n[📥 HTTP 响应] %s %s\n", method, url)
		fmt.Printf("状态码：%d | 耗时：%v\n", resp.StatusCode, elapsed)
		fmt.Printf("响应头:\n")
		for k, v := range resp.Header {
			fmt.Printf("  %s: %v\n", k, v)
		}
		if len(respBody) > 0 {
			var prettyJSON bytes.Buffer
			if err := json.Indent(&prettyJSON, respBody, "", "  "); err == nil {
				fmt.Printf("响应体:\n%s\n", prettyJSON.String())
			} else {
				fmt.Printf("响应体:\n%s\n", string(respBody))
			}
		} else {
			fmt.Printf("响应体: (空)\n")
		}
		fmt.Println(strings.Repeat("=", 80))
	}

	// 检查 HTTP 状态码
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP 错误：%d - %s", resp.StatusCode, string(respBody))
	}

	// 反序列化响应
	if err := json.Unmarshal(respBody, result); err != nil {
		return fmt.Errorf("反序列化响应失败：%w", err)
	}

	return nil
}
