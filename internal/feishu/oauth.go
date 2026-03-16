package feishu

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"feishu-ldap-server/internal/common"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

type OAuthTokenResponse struct {
	Code         int    `json:"code"`
	Msg          string `json:"msg"`
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	Scope        string `json:"scope"`
}

type UserInfoResponse struct {
	Code int    `json:"code"`
	Msg  string `json:"msg"`
	Data struct {
		UserID       string `json:"user_id"`
		UnionID      string `json:"union_id"`
		Name         string `json:"name"`
		EnName       string `json:"en_name"`
		Nickname     string `json:"nickname"`
		Email        string `json:"email"`
		Mobile       string `json:"mobile"`
		Gender       int    `json:"gender"`
		AvatarURL    string `json:"avatar_url"`
		AvatarThumb  string `json:"avatar_thumb"`
		AvatarMiddle string `json:"avatar_middle"`
		AvatarBig    string `json:"avatar_big"`
		OpenID       string `json:"open_id"`
	} `json:"data"`
}

func (c *Client) GetUserAccessToken(code, redirectURI string) (*OAuthTokenResponse, error) {
	reqBody := map[string]interface{}{
		"grant_type":    "authorization_code",
		"client_id":     c.appID,
		"client_secret": c.appSecret,
		"code":          code,
		"redirect_uri":  redirectURI,
	}

	var rawResult map[string]interface{}
	err := c.request("POST", ApiOAuthToken, reqBody, &rawResult)
	if err != nil {
		return nil, fmt.Errorf("请求失败: %w", err)
	}

	var result OAuthTokenResponse
	if err := common.MapToStruct(rawResult, &result); err != nil {
		return nil, fmt.Errorf("解析响应失败: %w", err)
	}

	if result.Code != 0 {
		return nil, fmt.Errorf("API 错误 [%d]: %s", result.Code, result.Msg)
	}

	return &result, nil
}

func (c *Client) GetUserInfo(userAccessToken string) (*UserInfoResponse, error) {
	endpoint := ApiUserInfo + "?user_id_type=union_id"

	var rawResult map[string]interface{}
	err := c.requestWithToken("GET", endpoint, nil, &rawResult, userAccessToken)
	if err != nil {
		return nil, fmt.Errorf("请求失败: %w", err)
	}

	var result UserInfoResponse
	if err := common.MapToStruct(rawResult, &result); err != nil {
		return nil, fmt.Errorf("解析响应失败: %w", err)
	}

	if result.Code != 0 {
		return nil, fmt.Errorf("API 错误 [%d]: %s", result.Code, result.Msg)
	}

	return &result, nil
}

func (c *Client) requestWithToken(method, endpoint string, body interface{}, result interface{}, userAccessToken string) error {
	var bodyBytes []byte
	var err error

	if body != nil {
		bodyBytes, err = json.Marshal(body)
		if err != nil {
			return fmt.Errorf("序列化请求体失败: %w", err)
		}
	}

	fullURL := FeishuAPIHost + endpoint

	var reqBodyReader io.Reader
	if bodyBytes != nil {
		reqBodyReader = bytes.NewReader(bodyBytes)
	}

	req, err := http.NewRequest(method, fullURL, reqBodyReader)
	if err != nil {
		return fmt.Errorf("创建请求失败: %w", err)
	}

	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	req.Header.Set("Authorization", "Bearer "+userAccessToken)

	httpClient := &http.Client{Timeout: 60 * time.Second}
	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("发送请求失败: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("读取响应失败: %w", err)
	}

	if err := json.Unmarshal(respBody, result); err != nil {
		return fmt.Errorf("解析响应失败: %w", err)
	}

	return nil
}

func BuildOAuthURL(appID, redirectURI, state string) string {
	params := url.Values{}
	params.Set("app_id", appID)
	params.Set("redirect_uri", redirectURI)
	params.Set("state", state)

	return fmt.Sprintf("%s?%s", OAuthAuthorizeURL, params.Encode())
}

func EncodeState(redirectURL string) string {
	return base64.URLEncoding.EncodeToString([]byte(redirectURL))
}

func DecodeState(state string) (string, error) {
	decoded, err := base64.URLEncoding.DecodeString(state)
	if err != nil {
		return "", err
	}
	return string(decoded), nil
}
