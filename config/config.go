package config

import (
	"strings"

	"github.com/spf13/viper"
)

type Config struct {
	Feishu struct {
		AppID              string `mapstructure:"app_id"`
		AppSecret          string `mapstructure:"app_secret"`
		SyncEnabled        bool   `mapstructure:"sync_enabled"`
		SyncInterval       string `mapstructure:"sync_interval"`
		UserPageSize       int    `mapstructure:"user_page_size"`
		DepartmentPageSize int    `mapstructure:"department_page_size"`
	} `mapstructure:"feishu"`
	LDAP struct {
		Enabled             bool   `mapstructure:"enabled"`
		Address             string `mapstructure:"address"`
		BaseDN              string `mapstructure:"base_dn"`
		ServiceBindDN       string `mapstructure:"service_bind_dn"`
		ServiceBindPassword string `mapstructure:"service_bind_password"`
	} `mapstructure:"ldap"`
	Server struct {
		HTTPPort    int    `mapstructure:"http_port"`
		BaseURL     string `mapstructure:"base_url"`
		CallbackURL string `mapstructure:"callback_url"`
	} `mapstructure:"server"`
}

func LoadConfig(configPath string) (*Config, error) {
	viper.SetConfigFile(configPath)

	if err := viper.ReadInConfig(); err != nil {
		return nil, err
	}

	var config Config
	if err := viper.Unmarshal(&config); err != nil {
		return nil, err
	}

	if config.Feishu.UserPageSize == 0 {
		config.Feishu.UserPageSize = 100
	}
	if config.Feishu.DepartmentPageSize == 0 {
		config.Feishu.DepartmentPageSize = 100
	}

	config.Server.CallbackURL = resolveCallbackURL(config.Server.BaseURL, config.Server.CallbackURL)

	return &config, nil
}

func resolveCallbackURL(baseURL, callbackURL string) string {
	if callbackURL == "" {
		return baseURL + "/api/auth/callback"
	}

	if strings.Contains(callbackURL, "://") {
		return callbackURL
	}

	if strings.HasPrefix(callbackURL, "/") {
		return strings.TrimSuffix(baseURL, "/") + callbackURL
	}

	return baseURL + "/" + callbackURL
}
