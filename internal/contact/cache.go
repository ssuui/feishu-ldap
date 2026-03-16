package contact

import (
	"context"
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Cache 通讯录内存缓存
type Cache struct {
	mu         sync.RWMutex
	data       *ContactData
	dataFile   string
	notifyFile string
	reloadChan chan struct{}
	stopChan   chan struct{}
	ctx        context.Context
	cancel     context.CancelFunc
}

// globalCache 全局缓存实例
var globalCache *Cache
var globalCacheMu sync.RWMutex

// InitCache 初始化全局缓存
func InitCache(dataFile string) (*Cache, error) {
	dir := filepath.Dir(dataFile)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, err
	}

	ctx, cancel := context.WithCancel(context.Background())

	cache := &Cache{
		data: &ContactData{
			Departments: make(map[string]*LDAPDepartment),
			Users:       make(map[string]*LDAPUser),
		},
		dataFile:   dataFile,
		notifyFile: filepath.Join(dir, "sync.notify"),
		reloadChan: make(chan struct{}, 1),
		stopChan:   make(chan struct{}),
		ctx:        ctx,
		cancel:     cancel,
	}

	if err := cache.loadFromFile(); err != nil {
		log.Printf("[Cache] 加载文件失败: %v (将使用空数据)", err)
	}

	globalCacheMu.Lock()
	globalCache = cache
	globalCacheMu.Unlock()

	return cache, nil
}

// GetCache 获取全局缓存实例
func GetCache() *Cache {
	globalCacheMu.RLock()
	defer globalCacheMu.RUnlock()
	return globalCache
}

// NotifyReload 通知全局缓存重载
func NotifyReload() {
	globalCacheMu.RLock()
	cache := globalCache
	globalCacheMu.RUnlock()

	if cache != nil {
		select {
		case cache.reloadChan <- struct{}{}:
			log.Println("[Cache] 已发送重载通知")
		default:
			log.Println("[Cache] 重载通知已在队列中")
		}
	}
}

// GetReloadChan 获取重载信号通道
func (c *Cache) GetReloadChan() chan<- struct{} {
	return c.reloadChan
}

// loadFromFile 从文件加载数据到内存
func (c *Cache) loadFromFile() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if _, err := os.Stat(c.dataFile); os.IsNotExist(err) {
		log.Printf("[Cache] 数据文件不存在: %s", c.dataFile)
		return nil
	}

	data, err := os.ReadFile(c.dataFile)
	if err != nil {
		return err
	}

	var contactData ContactData
	if err := json.Unmarshal(data, &contactData); err != nil {
		return err
	}

	if contactData.Departments == nil {
		contactData.Departments = make(map[string]*LDAPDepartment)
	}
	if contactData.Users == nil {
		contactData.Users = make(map[string]*LDAPUser)
	}

	c.data = &contactData
	log.Printf("[Cache] 从文件加载成功: %d 个部门, %d 个用户",
		len(c.data.Departments), len(c.data.Users))

	return nil
}

// Reload 从文件重新加载数据
func (c *Cache) Reload() error {
	return c.loadFromFile()
}

// StartReloadListener 启动重载监听器
// 监听两个信号源：
// 1. channel 信号（程序内部调用）
// 2. 通知文件变更（外部同步脚本触发）
func (c *Cache) StartReloadListener() {
	go func() {
		var lastNotifyMod time.Time

		ticker := time.NewTicker(1 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-c.ctx.Done():
				log.Println("[Cache] 重载监听器已停止")
				return
			case <-c.reloadChan:
				log.Println("[Cache] 收到重载信号，开始重新加载数据...")
				if err := c.Reload(); err != nil {
					log.Printf("[Cache] 重载失败: %v", err)
				} else {
					log.Println("[Cache] 数据重载成功")
				}
			case <-ticker.C:
				if info, err := os.Stat(c.notifyFile); err == nil {
					if info.ModTime().After(lastNotifyMod) {
						if !lastNotifyMod.IsZero() {
							log.Println("[Cache] 检测到同步通知文件变更，触发重载...")
							if err := c.Reload(); err != nil {
								log.Printf("[Cache] 重载失败: %v", err)
							} else {
								log.Println("[Cache] 数据重载成功")
							}
						}
						lastNotifyMod = info.ModTime()
					}
				}
			}
		}
	}()

	log.Println("[Cache] 重载监听器已启动")
}

// Stop 停止缓存
func (c *Cache) Stop() {
	c.cancel()
}

// Save 保存数据到文件
func (c *Cache) Save(data *ContactData) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	data.SyncTime = time.Now().Format(time.RFC3339)

	jsonData, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return err
	}

	tmpFile := c.dataFile + ".tmp"
	if err := os.WriteFile(tmpFile, jsonData, 0644); err != nil {
		return err
	}

	if err := os.Rename(tmpFile, c.dataFile); err != nil {
		return err
	}

	c.data = data

	log.Printf("[Cache] 数据已保存: %d 个部门, %d 个用户",
		len(data.Departments), len(data.Users))

	return nil
}

// GetData 获取当前缓存数据（只读）
func (c *Cache) GetData() *ContactData {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.data
}

// GetDepartment 根据 DN 获取部门
func (c *Cache) GetDepartment(dn string) *LDAPDepartment {
	c.mu.RLock()
	defer c.mu.RUnlock()

	for _, dept := range c.data.Departments {
		if dept.DN == dn {
			return dept
		}
	}
	return nil
}

// GetUser 根据 DN 获取用户
func (c *Cache) GetUser(dn string) *LDAPUser {
	c.mu.RLock()
	defer c.mu.RUnlock()

	for _, user := range c.data.Users {
		if user.DN == dn {
			return user
		}
	}
	return nil
}

// GetUserByMobile 根据手机号获取用户
func (c *Cache) GetUserByMobile(mobile string) *LDAPUser {
	c.mu.RLock()
	defer c.mu.RUnlock()

	normalizedMobile := normalizeMobile(mobile)
	for _, user := range c.data.Users {
		if user.Mobile == normalizedMobile {
			return user
		}
	}
	return nil
}

// GetUserByUID 根据 UID 获取用户
func (c *Cache) GetUserByUID(uid string) *LDAPUser {
	c.mu.RLock()
	defer c.mu.RUnlock()

	for _, user := range c.data.Users {
		if user.UID == uid {
			return user
		}
	}
	return nil
}

// GetUserByUserID 根据飞书 UserID 获取用户
func (c *Cache) GetUserByUserID(userID string) *LDAPUser {
	c.mu.RLock()
	defer c.mu.RUnlock()

	for _, user := range c.data.Users {
		if user.UserID == userID {
			return user
		}
	}
	return nil
}

// GetUserByUnionID 根据飞书 UnionID 获取用户
func (c *Cache) GetUserByUnionID(unionID string) *LDAPUser {
	c.mu.RLock()
	defer c.mu.RUnlock()

	for _, user := range c.data.Users {
		if user.UnionID == unionID {
			return user
		}
	}
	return nil
}

// GetAllUsers 获取所有用户
func (c *Cache) GetAllUsers() []*LDAPUser {
	c.mu.RLock()
	defer c.mu.RUnlock()

	users := make([]*LDAPUser, 0, len(c.data.Users))
	for _, user := range c.data.Users {
		users = append(users, user)
	}
	return users
}

// GetAllDepartments 获取所有部门
func (c *Cache) GetAllDepartments() []*LDAPDepartment {
	c.mu.RLock()
	defer c.mu.RUnlock()

	depts := make([]*LDAPDepartment, 0, len(c.data.Departments))
	for _, dept := range c.data.Departments {
		depts = append(depts, dept)
	}
	return depts
}

// GetDepartmentTree 获取部门树
func (c *Cache) GetDepartmentTree() *DepartmentTreeNode {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.data.DeptTree
}

// GetUsersByDepartment 获取部门下的用户
func (c *Cache) GetUsersByDepartment(deptDN string) []*LDAPUser {
	c.mu.RLock()
	defer c.mu.RUnlock()

	var users []*LDAPUser
	for _, user := range c.data.Users {
		if user.OU == deptDN {
			users = append(users, user)
		}
	}
	return users
}

// GetStats 获取缓存统计信息
func (c *Cache) GetStats() map[string]interface{} {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return map[string]interface{}{
		"total_departments": len(c.data.Departments),
		"total_users":       len(c.data.Users),
		"sync_time":         c.data.SyncTime,
		"version":           c.data.Version,
		"base_dn":           c.data.BaseDN,
	}
}
