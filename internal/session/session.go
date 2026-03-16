package session

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const (
	TokenValidityDays = 30
)

type Session struct {
	Token     string    `json:"token"`
	UserID    string    `json:"user_id"`
	UnionID   string    `json:"union_id"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

type SessionData struct {
	Sessions map[string]*Session `json:"sessions"`
}

type Manager struct {
	mu       sync.RWMutex
	sessions map[string]*Session
	dataFile string
}

var globalManager *Manager
var globalManagerMu sync.RWMutex

func InitManager(dataFile string) (*Manager, error) {
	dir := filepath.Dir(dataFile)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, err
	}

	m := &Manager{
		sessions: make(map[string]*Session),
		dataFile: dataFile,
	}

	if err := m.loadFromFile(); err != nil {
		log.Printf("[Session] 加载文件失败: %v (将使用空数据)", err)
	}

	m.cleanExpired()

	globalManagerMu.Lock()
	globalManager = m
	globalManagerMu.Unlock()

	return m, nil
}

func GetManager() *Manager {
	globalManagerMu.RLock()
	defer globalManagerMu.RUnlock()
	return globalManager
}

func (m *Manager) loadFromFile() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, err := os.Stat(m.dataFile); os.IsNotExist(err) {
		return nil
	}

	data, err := os.ReadFile(m.dataFile)
	if err != nil {
		return err
	}

	var sessionData SessionData
	if err := json.Unmarshal(data, &sessionData); err != nil {
		return err
	}

	if sessionData.Sessions == nil {
		sessionData.Sessions = make(map[string]*Session)
	}

	m.sessions = sessionData.Sessions
	log.Printf("[Session] 从文件加载成功: %d 个会话", len(m.sessions))

	return nil
}

func (m *Manager) saveToFile() error {
	m.mu.RLock()
	defer m.mu.RUnlock()

	sessionData := SessionData{
		Sessions: m.sessions,
	}

	jsonData, err := json.MarshalIndent(sessionData, "", "  ")
	if err != nil {
		return err
	}

	tmpFile := m.dataFile + ".tmp"
	if err := os.WriteFile(tmpFile, jsonData, 0644); err != nil {
		return err
	}

	return os.Rename(tmpFile, m.dataFile)
}

func (m *Manager) cleanExpired() {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()
	count := 0
	for token, session := range m.sessions {
		if session.ExpiresAt.Before(now) {
			delete(m.sessions, token)
			count++
		}
	}

	if count > 0 {
		log.Printf("[Session] 清理了 %d 个过期会话", count)
		m.saveToFile()
	}
}

func generateToken() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}

	hash := sha256.Sum256(bytes)
	return hex.EncodeToString(hash[:]), nil
}

func (m *Manager) CreateSession(userID, unionID string) (*Session, error) {
	token, err := generateToken()
	if err != nil {
		return nil, err
	}

	now := time.Now()
	session := &Session{
		Token:     token,
		UserID:    userID,
		UnionID:   unionID,
		CreatedAt: now,
		ExpiresAt: now.AddDate(0, 0, TokenValidityDays),
	}

	m.mu.Lock()
	m.sessions[token] = session
	m.mu.Unlock()

	if err := m.saveToFile(); err != nil {
		log.Printf("[Session] 保存文件失败: %v", err)
	}

	log.Printf("[Session] 创建会话: userID=%s, token=%s...", userID, token[:16])

	return session, nil
}

func (m *Manager) ValidateToken(token string) (*Session, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	session, exists := m.sessions[token]
	if !exists {
		return nil, false
	}

	if time.Now().After(session.ExpiresAt) {
		return nil, false
	}

	return session, true
}

func (m *Manager) GetSession(token string) *Session {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return m.sessions[token]
}

func (m *Manager) DeleteSession(token string) {
	m.mu.Lock()
	delete(m.sessions, token)
	m.mu.Unlock()

	m.saveToFile()
}

func (m *Manager) GetSessionCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.sessions)
}
