package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"feishu-ldap-server/config"
	"feishu-ldap-server/internal/contact"
	"feishu-ldap-server/internal/feishu"
)

func main() {
	// 命令行参数
	configPath := flag.String("config", "config/config.yaml", "配置文件路径")
	dataFile := flag.String("data", "runtime/contacts.json", "数据文件路径")
	notifyFile := flag.String("notify", "runtime/sync.notify", "通知文件路径（用于通知 LDAP 服务重载）")
	verbose := flag.Bool("v", false, "显示详细输出")
	flag.Parse()

	// 设置日志格式
	log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)

	// 加载配置
	log.Printf("[Sync] 加载配置文件: %s", *configPath)
	cfg, err := config.LoadConfig(*configPath)
	if err != nil {
		log.Fatalf("[Sync] 加载配置失败: %v", err)
	}

	// 检查飞书配置
	if cfg.Feishu.AppID == "" || cfg.Feishu.AppSecret == "" {
		log.Fatal("[Sync] 飞书配置不完整，请检查 app_id 和 app_secret")
	}

	// 设置调试模式
	if *verbose {
		feishu.DebugRequest = true
		feishu.DebugResponse = true
	}

	// 创建飞书客户端
	log.Println("[Sync] 初始化飞书客户端...")
	client := feishu.NewClient(cfg.Feishu.AppID, cfg.Feishu.AppSecret)

	// 测试连接（获取 token）
	token, err := client.GetToken()
	if err != nil {
		log.Fatalf("[Sync] 获取飞书 Token 失败: %v", err)
	}
	log.Printf("[Sync] 飞书 Token 获取成功: %s...", token[:min(20, len(token))])

	// 初始化缓存
	log.Printf("[Sync] 初始化缓存: %s", *dataFile)
	cache, err := contact.InitCache(*dataFile)
	if err != nil {
		log.Fatalf("[Sync] 初始化缓存失败: %v", err)
	}

	// 创建同步器
	syncer := contact.NewSyncer(client, cache, cfg.LDAP.BaseDN)

	// 执行同步
	log.Println("[Sync] 开始同步通讯录...")
	startTime := time.Now()

	result, err := syncer.Sync()
	if err != nil {
		log.Fatalf("[Sync] 同步失败: %v", err)
	}

	elapsed := time.Since(startTime)

	// 打印结果
	fmt.Println()
	fmt.Println("========================================")
	fmt.Println("           同步完成")
	fmt.Println("========================================")
	fmt.Printf("同步时间:     %s\n", result.SyncTime)
	fmt.Printf("耗时:         %v\n", elapsed)
	fmt.Printf("部门总数:     %d\n", result.TotalDepartments)
	fmt.Printf("用户总数:     %d\n", result.TotalUsers)
	fmt.Printf("新增用户:     %d\n", result.NewUsers)
	fmt.Printf("更新用户:     %d\n", result.UpdatedUsers)
	fmt.Printf("新TOTP生成:   %d\n", result.NewTOTPGenerated)

	if len(result.Errors) > 0 {
		fmt.Printf("\n错误/警告:\n")
		for _, e := range result.Errors {
			fmt.Printf("  - %s\n", e)
		}
	}

	fmt.Println("========================================")
	fmt.Printf("数据文件:     %s\n", *dataFile)

	// 写入通知文件（通知 LDAP 服务重载）
	if err := writeNotifyFile(*notifyFile, result); err != nil {
		log.Printf("[Sync] 写入通知文件失败: %v", err)
	} else {
		fmt.Printf("通知文件:     %s\n", *notifyFile)
	}

	fmt.Println("========================================")
}

// writeNotifyFile 写入通知文件
// LDAP 服务可以监听此文件的变化来触发重载
func writeNotifyFile(notifyFile string, result *contact.SyncResult) error {
	notify := map[string]interface{}{
		"sync_time":         result.SyncTime,
		"total_departments": result.TotalDepartments,
		"total_users":       result.TotalUsers,
		"action":            "reload",
	}

	data, err := json.MarshalIndent(notify, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(notifyFile, data, 0644)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
