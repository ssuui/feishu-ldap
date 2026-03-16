package ldap

import (
	"context"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/jimlambrt/gldap"

	"feishu-ldap-server/internal/contact"
)

type Server struct {
	server              *gldap.Server
	address             string
	baseDN              string
	serviceBindDN       string
	serviceBindPassword string
	cache               *contact.Cache
	ctx                 context.Context
	cancel              context.CancelFunc
	wg                  sync.WaitGroup
	sessions            *sessionManager
}

type Config struct {
	Address             string
	BaseDN              string
	ServiceBindDN       string
	ServiceBindPassword string
	Cache               *contact.Cache
}

type session struct {
	isService bool
	userUID   string
}

type sessionManager struct {
	mu       sync.RWMutex
	sessions map[string]*session
}

func newSessionManager() *sessionManager {
	return &sessionManager{
		sessions: make(map[string]*session),
	}
}

func (sm *sessionManager) set(connID string, s *session) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.sessions[connID] = s
}

func (sm *sessionManager) get(connID string) *session {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return sm.sessions[connID]
}

func (sm *sessionManager) delete(connID string) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	delete(sm.sessions, connID)
}

func NewServer(cfg Config) (*Server, error) {
	ctx, cancel := context.WithCancel(context.Background())

	server, err := gldap.NewServer()
	if err != nil {
		cancel()
		return nil, fmt.Errorf("failed to create LDAP server: %w", err)
	}

	mux, err := gldap.NewMux()
	if err != nil {
		cancel()
		return nil, fmt.Errorf("failed to create LDAP mux: %w", err)
	}

	authenticator := NewAuthenticator(cfg.BaseDN, cfg.ServiceBindDN, cfg.ServiceBindPassword)
	authenticator.SetCache(cfg.Cache)

	s := &Server{
		server:              server,
		address:             cfg.Address,
		baseDN:              cfg.BaseDN,
		serviceBindDN:       cfg.ServiceBindDN,
		serviceBindPassword: cfg.ServiceBindPassword,
		cache:               cfg.Cache,
		ctx:                 ctx,
		cancel:              cancel,
		sessions:            newSessionManager(),
	}

	mux.Bind(func(w *gldap.ResponseWriter, r *gldap.Request) {
		s.handleBind(w, r, authenticator)
	})

	mux.Search(func(w *gldap.ResponseWriter, r *gldap.Request) {
		s.handleSearch(w, r)
	})

	mux.DefaultRoute(func(w *gldap.ResponseWriter, r *gldap.Request) {
		log.Printf("[LDAP] Unhandled request type: %T", r)
		resp := r.NewResponse(gldap.WithDiagnosticMessage("Operation not supported"))
		resp.SetResultCode(gldap.ResultUnwillingToPerform)
		w.Write(resp)
	})

	if err := server.Router(mux); err != nil {
		cancel()
		return nil, fmt.Errorf("failed to set router: %w", err)
	}

	return s, nil
}

func (s *Server) Start() error {
	log.Printf("[LDAP] Server starting on %s", s.address)
	log.Printf("[LDAP] Base DN: %s", s.baseDN)
	log.Printf("[LDAP] Service Bind DN: %s", s.serviceBindDN)

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		if err := s.server.Run(s.address); err != nil {
			select {
			case <-s.ctx.Done():
			default:
				log.Printf("[LDAP] Server error: %v", err)
			}
		}
	}()

	time.Sleep(100 * time.Millisecond)

	if !s.server.Ready() {
		return fmt.Errorf("server failed to start")
	}

	log.Printf("[LDAP] Server started successfully")
	return nil
}

func (s *Server) Stop() error {
	log.Println("[LDAP] Stopping server...")

	s.cancel()

	if err := s.server.Stop(); err != nil {
		log.Printf("[LDAP] Error stopping server: %v", err)
	}

	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		log.Println("[LDAP] Server stopped gracefully")
		return nil
	case <-time.After(3 * time.Second):
		log.Println("[LDAP] Server stopped with timeout")
		return fmt.Errorf("timeout while stopping server")
	}
}

func (s *Server) handleBind(w *gldap.ResponseWriter, r *gldap.Request, authenticator *Authenticator) {
	bindMsg, err := r.GetSimpleBindMessage()
	if err != nil {
		log.Printf("[LDAP] Failed to get bind message: %v", err)
		resp := r.NewBindResponse(gldap.WithDiagnosticMessage("Invalid bind request"))
		resp.SetResultCode(gldap.ResultProtocolError)
		w.Write(resp)
		return
	}

	log.Printf("[LDAP] Bind request from DN: %s", bindMsg.UserName)

	result, err := authenticator.Authenticate(bindMsg.UserName, string(bindMsg.Password))
	if err != nil {
		log.Printf("[LDAP] Authentication error: %v", err)
		resp := r.NewBindResponse(gldap.WithDiagnosticMessage("Authentication error"))
		resp.SetResultCode(gldap.ResultOperationsError)
		w.Write(resp)
		return
	}

	if result.Success {
		connID := r.ConnectionID()
		sess := &session{
			isService: result.IsService,
		}
		if !result.IsService {
			sess.userUID = extractUIDFromDN(bindMsg.UserName)
			log.Printf("[LDAP] User session created: connID=%d, userUID=%s", connID, sess.userUID)
		} else {
			log.Printf("[LDAP] Service session created: connID=%d", connID)
		}
		s.sessions.set(fmt.Sprintf("%d", connID), sess)

		if result.IsService {
			log.Printf("[LDAP] Step 1: Service connection successful")
		} else {
			log.Printf("[LDAP] Step 3: User login successful - User %s authenticated", result.Username)
		}
		resp := r.NewBindResponse()
		resp.SetResultCode(gldap.ResultSuccess)
		w.Write(resp)
	} else {
		log.Printf("[LDAP] Bind failed for DN: %s - %s", bindMsg.UserName, result.Reason)
		resp := r.NewBindResponse(gldap.WithDiagnosticMessage(result.Reason))
		resp.SetResultCode(gldap.ResultInvalidCredentials)
		w.Write(resp)
	}
}

const (
	ScopeBaseObject   = 0
	ScopeSingleLevel  = 1
	ScopeWholeSubtree = 2
)

func (s *Server) handleSearch(w *gldap.ResponseWriter, r *gldap.Request) {
	searchMsg, err := r.GetSearchMessage()
	if err != nil {
		log.Printf("[LDAP] Failed to get search message: %v", err)
		resp := r.NewSearchDoneResponse(gldap.WithDiagnosticMessage("Invalid search request"))
		resp.SetResultCode(gldap.ResultProtocolError)
		w.Write(resp)
		return
	}

	searchBaseDN := searchMsg.BaseDN
	filter := searchMsg.Filter
	scope := int(searchMsg.Scope)

	log.Printf("[LDAP] Step 2: Search request - BaseDN: %s, Filter: %s, Scope: %d",
		searchBaseDN, filter, scope)

	if isSchemaQuery(searchBaseDN) {
		searchSchema(w, r, searchBaseDN, filter, scope, s.baseDN)
		return
	}

	if searchBaseDN == "" {
		searchRootDSE(w, r, s.baseDN)
		return
	}

	if s.cache == nil {
		log.Printf("[LDAP] Warning: Cache not initialized")
		sendSearchDone(w, r, gldap.ResultSuccess)
		return
	}

	data := s.cache.GetData()
	if data == nil {
		log.Printf("[LDAP] Warning: No data in cache")
		sendSearchDone(w, r, gldap.ResultSuccess)
		return
	}

	connID := fmt.Sprintf("%d", r.ConnectionID())
	sess := s.sessions.get(connID)

	if sess != nil {
		log.Printf("[LDAP] Search with session: connID=%s, isService=%v, userUID=%s", connID, sess.isService, sess.userUID)
	} else {
		log.Printf("[LDAP] Search without session: connID=%s", connID)
	}

	filterType := parseFilterType(filter)

	switch filterType {
	case filterTypeUser:
		s.searchUsersWithPermission(w, r, filter, scope, sess)
	case filterTypeDepartment:
		searchDepartments(w, r, s.cache, searchBaseDN, filter, scope)
	default:
		s.searchUsersWithPermission(w, r, filter, scope, sess)
		searchDepartments(w, r, s.cache, searchBaseDN, filter, scope)
	}

	sendSearchDone(w, r, gldap.ResultSuccess)
}

func (s *Server) searchUsersWithPermission(w *gldap.ResponseWriter, r *gldap.Request, filter string, scope int, sess *session) {
	users := s.cache.GetAllUsers()
	count := 0
	filtered := 0

	for _, user := range users {
		if !matchScope(user.DN, s.baseDN, scope) {
			continue
		}

		if !matchFilter(user, filter) {
			continue
		}

		if sess != nil && !sess.isService {
			if sess.userUID != user.UID {
				filtered++
				continue
			}
		}

		e := r.NewSearchResponseEntry(user.DN)
		e.AddAttribute("objectClass", user.ObjectClass)
		e.AddAttribute("cn", []string{user.CN})
		e.AddAttribute("sn", []string{user.SN})
		e.AddAttribute("uid", []string{user.UID})
		e.AddAttribute("mail", []string{user.Email})
		e.AddAttribute("mobile", []string{user.Mobile})
		e.AddAttribute("displayName", []string{user.Name})
		w.Write(e)
		count++
	}

	log.Printf("[LDAP] Search users: returned %d entries, filtered %d (filter: %s, isService: %v)", count, filtered, filter, sess == nil || sess.isService)
}

type filterType int

const (
	filterTypeUnknown filterType = iota
	filterTypeUser
	filterTypeDepartment
	filterTypeAll
)

func parseFilterType(filter string) filterType {
	filter = strings.ToLower(filter)

	if strings.Contains(filter, "person") ||
		strings.Contains(filter, "inetorgperson") ||
		strings.Contains(filter, "organizationalperson") {
		return filterTypeUser
	}

	if strings.Contains(filter, "organizationalunit") {
		return filterTypeDepartment
	}

	if strings.Contains(filter, "uid=") ||
		strings.Contains(filter, "cn=") ||
		strings.Contains(filter, "mail=") ||
		strings.Contains(filter, "mobile=") ||
		strings.Contains(filter, "samaccountname=") {
		return filterTypeUser
	}

	if strings.Contains(filter, "ou=") && !strings.Contains(filter, "uid=") {
		return filterTypeDepartment
	}

	if strings.Contains(filter, "objectclass=*") {
		return filterTypeAll
	}

	return filterTypeAll
}

type LDAPFilter struct {
	Attribute string
	Value     string
}

func parseSimpleFilter(filter string) *LDAPFilter {
	filter = strings.Trim(filter, "()")

	idx := strings.Index(filter, "=")
	if idx == -1 {
		return nil
	}

	attr := strings.TrimSpace(filter[:idx])
	value := strings.TrimSpace(filter[idx+1:])

	return &LDAPFilter{
		Attribute: strings.ToLower(attr),
		Value:     value,
	}
}

func matchFilter(user *contact.LDAPUser, filter string) bool {
	if strings.Contains(strings.ToLower(filter), "objectclass=*") {
		return true
	}

	f := parseSimpleFilter(filter)
	if f == nil {
		return true
	}

	switch f.Attribute {
	case "uid":
		return strings.EqualFold(user.UID, f.Value)
	case "cn":
		return strings.EqualFold(user.CN, f.Value)
	case "sn":
		return strings.EqualFold(user.SN, f.Value)
	case "mail":
		return strings.EqualFold(user.Email, f.Value)
	case "mobile":
		return strings.EqualFold(user.Mobile, f.Value)
	case "displayname":
		return strings.EqualFold(user.Name, f.Value)
	case "objectclass":
		for _, oc := range user.ObjectClass {
			if strings.EqualFold(oc, f.Value) {
				return true
			}
		}
		return false
	case "samaccountname":
		return strings.EqualFold(user.UID, f.Value)
	default:
		return true
	}
}

func matchDeptFilter(dept *contact.LDAPDepartment, filter string) bool {
	if strings.Contains(strings.ToLower(filter), "objectclass=*") {
		return true
	}

	f := parseSimpleFilter(filter)
	if f == nil {
		return true
	}

	switch f.Attribute {
	case "ou":
		return strings.EqualFold(dept.OU, f.Value)
	case "description":
		return strings.EqualFold(dept.Name, f.Value)
	case "objectclass":
		for _, oc := range dept.ObjectClass {
			if strings.EqualFold(oc, f.Value) {
				return true
			}
		}
		return false
	default:
		return true
	}
}

func searchDepartments(w *gldap.ResponseWriter, r *gldap.Request, cache *contact.Cache, searchBaseDN, filter string, scope int) {
	depts := cache.GetAllDepartments()
	count := 0

	for _, dept := range depts {
		if !matchScope(dept.DN, searchBaseDN, scope) {
			continue
		}

		if !matchDeptFilter(dept, filter) {
			continue
		}

		e := r.NewSearchResponseEntry(dept.DN)
		e.AddAttribute("objectClass", dept.ObjectClass)
		e.AddAttribute("ou", []string{dept.OU})
		e.AddAttribute("description", []string{dept.Name})
		w.Write(e)
		count++
	}

	log.Printf("[LDAP] Search departments: returned %d entries (filter: %s)", count, filter)
}

func matchScope(entryDN, searchBaseDN string, scope int) bool {
	entryDN = normalizeDN(entryDN)
	searchBaseDN = normalizeDN(searchBaseDN)

	switch scope {
	case ScopeBaseObject:
		return entryDN == searchBaseDN

	case ScopeSingleLevel:
		if !strings.HasSuffix(entryDN, searchBaseDN) {
			return false
		}
		prefix := strings.TrimSuffix(entryDN, ","+searchBaseDN)
		if prefix == entryDN || prefix == "" {
			return false
		}
		return !strings.Contains(prefix, ",")

	case ScopeWholeSubtree:
		if entryDN == searchBaseDN {
			return true
		}
		return strings.HasSuffix(entryDN, ","+searchBaseDN)

	default:
		return strings.HasSuffix(entryDN, searchBaseDN)
	}
}

func normalizeDN(dn string) string {
	dn = strings.ToLower(strings.TrimSpace(dn))

	replacements := []struct {
		from string
		to   string
	}{
		{"\\2b", "+"},
		{"\\2c", ","},
		{"\\3d", "="},
		{"\\3c", "<"},
		{"\\3e", ">"},
		{"\\3b", ";"},
		{"\\22", "\""},
		{"\\5c", "\\"},
	}

	for _, r := range replacements {
		dn = strings.ReplaceAll(dn, r.from, r.to)
	}

	return dn
}

func sendSearchDone(w *gldap.ResponseWriter, r *gldap.Request, resultCode int) {
	done := r.NewSearchDoneResponse()
	done.SetResultCode(resultCode)
	w.Write(done)
}
