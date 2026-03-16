# 飞书 LDAP 服务

一个基于 Go 语言开发的轻量级 LDAP 服务，实现了飞书通讯录与标准 LDAP 协议的无缝对接，支持通过飞书 OAuth 登录获取动态验证码进行无固定密码登录。

## 核心功能

### 1. 标准 LDAP 服务
- 提供符合 LDAP v3 协议标准的认证服务
- 监听 389 端口，支持第三方应用（如 VPN、NAS、Jira 等）通过 LDAP 进行用户认证
- 实现动态密码验证机制，支持 TOTP（基于时间的一次性密码）

### 2. 飞书通讯录同步
- 对接飞书开放平台 API，自动同步企业通讯录
- 支持用户和部门信息的定时同步(提供脚本调用)
- 自动处理分页查询，支持大规模企业用户同步
- Token 自动管理，支持缓存和自动刷新

### 3. HTTP API 服务
- 提供 RESTful HTTP 接口，供飞书 Web 应用调用
- 支持飞书 OAuth 2.0 登录认证
- 用户登录后可获取当前时间的动态验证码
- Token 有效期 30 天，支持持久化存储

## 设计理念

### 无固定密码登录方案

本项目的核心创新在于实现了**无固定密码的 LDAP 登录**方案：

1. **秘钥生成**：在同步飞书用户到服务器缓存时，为每个用户生成随机的 TOTP 秘钥
   - 每次同步时秘钥可以重新生成
   - 用户完全无感知，无需记忆任何密码

2. **登录流程**：
   - 用户在第三方应用（如 VPN）选择 LDAP 登录
   - 输入用户飞书手机号 (13800138000)
   - 打开飞书应用（Web/小程序）获取当前 6 位动态验证码
   - 在第三方应用输入 固定前缀 `totp_pwd_` + 动态验证码完成登录 有效防止三方应用缓存密码

3. **安全优势**：
   - 无需记忆密码，避免密码泄露风险
   - 动态验证码每 30 秒变化，即使被截获也很快失效
   - 飞书应用本身已通过飞书免登录认证，双重保障

### 技术架构

```
┌─────────────────┐
│   第三方应用     │
│  (VPN/NAS等)    │
└────────┬────────┘
         │ LDAP 认证 (端口 389)
         ▼
┌─────────────────┐
│  LDAP Server    │
│  TOTP 验证      │
└────────┬────────┘
         │
         ▼
┌─────────────────┐        ┌─────────────────┐
│   用户缓存       │        │  会话管理        │
│  (JSON 文件)    │        │  (JSON 文件)    │
└────────┬────────┘        └────────┬────────┘
         │                          │
         │ 同步用户                  │ OAuth 登录
         ▼                          ▼
┌─────────────────┐        ┌─────────────────┐
│  飞书 API 客户端 │        │  HTTP Server    │
└────────┬────────┘        │  (端口 8080)    │
         │                 └────────┬────────┘
         │                          │
         │                          ▼
         │                 ┌─────────────────┐
         └─────────────────│  飞书应用        │
                           │ (OAuth 登录)    │
                           └─────────────────┘
```

## 项目结构

```
FeiShu-LDAP-Service/
├── cmd/
│   ├── main.go              # 主程序入口
│   └── sync/
│       └── contact.go       # 通讯录同步命令
├── config/
│   ├── config.go            # 配置结构体定义
│   ├── config.yaml          # 实际配置文件
│   └── config.example.yaml  # 配置示例
├── internal/
│   ├── common/
│   │   ├── response.go      # HTTP 响应辅助函数
│   │   └── utils.go         # 通用工具函数
│   ├── contact/
│   │   ├── cache.go         # 通讯录缓存管理
│   │   ├── sync.go          # 同步逻辑
│   │   └── types.go         # 数据类型定义
│   ├── feishu/
│   │   ├── client.go        # 飞书 API 客户端
│   │   ├── const.go         # 常量定义
│   │   ├── department.go    # 部门同步逻辑
│   │   ├── oauth.go         # OAuth 认证逻辑
│   │   └── user.go          # 用户同步逻辑
│   ├── http/
│   │   ├── handlers/
│   │   │   ├── auth.go      # OAuth 登录处理
│   │   │   └── totp.go      # TOTP 验证码处理
│   │   ├── middleware/
│   │   │   └── auth.go      # Token 认证中间件
│   │   └── server.go        # HTTP 服务器
│   ├── ldap/
│   │   ├── auth.go          # LDAP 认证逻辑
│   │   ├── schema.go        # LDAP Schema 定义
│   │   └── server.go        # LDAP 服务器
│   └── session/
│       └── session.go       # 会话管理
├── runtime/
│   ├── contacts.json        # 通讯录数据文件
│   ├── sessions.json        # 会话数据文件
│   └── sync.notify          # 同步通知文件
├── go.mod
├── go.sum
└── README.md
```

## 技术栈

### 核心依赖

| 依赖 | 用途 |
|------|------|
| Go 1.26.1 | 编程语言 |
| github.com/gin-gonic/gin | HTTP Web 框架 |
| github.com/pquerna/otp | TOTP 动态验证码生成 |
| github.com/spf13/viper | 配置文件管理 |
| github.com/jimlambrt/gldap | LDAP 服务器实现 |

## 配置说明

配置文件位于 `config/config.yaml`，主要配置项如下：

```yaml
# 飞书配置
feishu:
  app_id: "cli_xxxxxxxxxxxxx"              # 飞书应用 App ID
  app_secret: "xxxxxxxxxxxxxxxxxxxxxxxx"   # 飞书应用 App Secret
  sync_enabled: true                       # 是否启用自动同步
  user_page_size: 50                       # 用户分页大小
  department_page_size: 50                 # 部门分页大小

# LDAP 配置
ldap:
  enabled: true                            # 是否启用 LDAP 服务
  address: "0.0.0.0:389"                   # LDAP 监听地址
  base_dn: "dc=example,dc=com"             # 基础 DN
  service_bind_dn: "cn=admin,dc=example,dc=com"  # 服务连接账户 DN
  service_bind_password: "admin_password"  # 服务连接密码

# 服务器配置
server:
  http_port: 8080                          # HTTP 服务端口
  base_url: "http://localhost:8080"        # 服务端基础 URL
  callback_url: "/api/auth/callback"       # OAuth 回调 URL（支持 path 或完整 URL）
```

### callback_url 配置说明

`callback_url` 支持两种格式：

| 格式 | 示例 | 说明 |
|------|------|------|
| 路径 | `/api/auth/callback` | 自动拼接 `base_url`，最终为 `http://localhost:8080/api/auth/callback` |
| 完整 URL | `https://example.com/callback` | 直接使用，不拼接 `base_url` |

## 快速开始

### 1. 环境准备

- Go 1.26.1 或更高版本

### 2. 安装依赖

```bash
go mod download
```

### 3. 配置文件

复制 `config/config.example.yaml` 为 `config/config.yaml`，并填入实际的飞书应用配置：

```bash
cp config/config.example.yaml config/config.yaml
```

### 4. 同步通讯录

```bash
go run cmd/sync/contact.go -config config/config.yaml -v
```

### 5. 运行服务

```bash
go run cmd/main.go
```

服务启动后：
- LDAP 服务监听 `0.0.0.0:389`
- HTTP API 服务监听 `0.0.0.0:8080`

## API 接口

### 公开接口（无需登录）

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/health` | 健康检查 |
| GET | `/api/auth/login` | 飞书 OAuth 登录入口 |
| GET | `/api/auth/callback` | 飞书 OAuth 回调 |

### 需要认证的接口

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/totp/code` | 获取当前用户的 TOTP 验证码 |
| GET | `/api/user/info` | 获取当前用户信息 |

### OAuth 登录流程

1. 前端检测用户未登录（无 Token）
2. 重定向到 `/api/auth/login?redirect_uri=http://your-frontend.com`
3. 服务端构建飞书授权 URL 并重定向
4. 用户在飞书授权页面同意授权
5. 飞书回调 `/api/auth/callback?code=xxx&state=xxx`
6. 服务端用 code 换取 user_access_token，获取用户信息
7. 服务端创建会话，生成 Token
8. 重定向回前端，携带 `?token=xxx`

### TOTP 验证码接口

请求：
```http
GET /api/totp/code
Token: <your-token>
```

响应：
```json
{
  "success": true,
  "data": {
    "code": "123456",
    "expires_in": 25,
    "user_id": "ou_xxx",
    "user_name": "张三",
    "generated_at": "2026-03-16T12:00:00Z",
    "expires_at": "2026-03-16T12:00:30Z"
  }
}
```

## LDAP 认证流程

### 标准绑定（Bind）请求

```
DN: uid={username},dc=example,dc=com
Password: {固定前缀}{6位动态验证码}
```

例如：
```
DN: uid=zhangsan,dc=example,dc=com
Password: totp_pwd_123456
```

### 认证逻辑

1. 解析 Bind 请求中的用户名和密码
2. 从缓存中获取该用户的 TOTP 秘钥
3. 使用秘钥验证密码中的动态验证码是否正确
4. 验证成功返回 LDAP Success，失败返回 Invalid Credentials

## 数据存储

本项目使用 JSON 文件进行数据持久化，无需额外数据库：

| 文件 | 说明 |
|------|------|
| `runtime/contacts.json` | 通讯录数据（用户、部门、TOTP 秘钥） |
| `runtime/sessions.json` | 会话数据（Token、用户 ID、过期时间） |
| `runtime/sync.notify` | 同步通知文件（用于触发重载） |

## 安全建议

1. **网络隔离**：LDAP 服务应部署在内网，避免直接暴露到公网
2. **HTTPS**：HTTP API 接口建议使用 HTTPS 加密传输
3. **Token 保护**：飞书应用的 App Secret 应妥善保管，避免泄露
4. **访问控制**：飞书应用应设置访问权限，仅允许企业内部用户访问
5. **日志审计**：记录所有 LDAP 认证请求，便于安全审计

## 许可证

MIT License
