package admin

import (
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"
)

type mfaChallengeType int

const (
	// 登录场景：已有 MFA，要求输入 TOTP 验证
	mfaChallengeTypeLoginVerify mfaChallengeType = iota
	// 登录场景：未配置 MFA，要求先进行首次配置
	mfaChallengeTypeLoginSetup
	// 登录场景：首次配置中，等待输入验证码确认绑定
	mfaChallengeTypeLoginSetupConfirm
	// 管理场景：管理员为指定用户开启 MFA
	mfaChallengeTypeAdminSetup
)

type mfaChallenge struct {
	ChallengeID   string
	ChallengeType mfaChallengeType
	UserID        int
	Username      string
	ExpiresAt     time.Time
	Attempts      int

	// setup 场景：暂存 Base32 TOTP secret（未确认，尚未写入数据库）
	TempSecret string
}

const (
	mfaGCInterval       = 1 * time.Minute
	mfaChallengeIDBytes = 16
)

type mfaChallengeStore struct {
	mu      sync.RWMutex
	entries map[string]*mfaChallenge
	stopGC  chan struct{}
}

func newMFAChallengeStore() *mfaChallengeStore {
	s := &mfaChallengeStore{
		entries: make(map[string]*mfaChallenge),
		stopGC:  make(chan struct{}),
	}
	go s.gcLoop()
	return s
}

func (s *mfaChallengeStore) gcLoop() {
	ticker := time.NewTicker(mfaGCInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			s.evictExpired()
		case <-s.stopGC:
			return
		}
	}
}

func (s *mfaChallengeStore) evictExpired() {
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, c := range s.entries {
		if now.After(c.ExpiresAt) {
			delete(s.entries, id)
		}
	}
}

func generateChallengeID() (string, error) {
	b := make([]byte, mfaChallengeIDBytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func (s *mfaChallengeStore) Create(ct mfaChallengeType, userID int, username string) (*mfaChallenge, error) {
	return s.CreateWithTTL(5*time.Minute, ct, userID, username)
}

func (s *mfaChallengeStore) CreateWithTTL(ttl time.Duration, ct mfaChallengeType, userID int, username string) (*mfaChallenge, error) {
	id, err := generateChallengeID()
	if err != nil {
		return nil, err
	}
	c := &mfaChallenge{
		ChallengeID:   id,
		ChallengeType: ct,
		UserID:        userID,
		Username:      username,
		ExpiresAt:     time.Now().Add(ttl),
	}
	s.mu.Lock()
	s.entries[id] = c
	s.mu.Unlock()
	return c, nil
}

func (s *mfaChallengeStore) Get(challengeID string) (*mfaChallenge, bool) {
	s.mu.RLock()
	c, ok := s.entries[challengeID]
	s.mu.RUnlock()
	if !ok {
		return nil, false
	}
	if time.Now().After(c.ExpiresAt) {
		s.Delete(challengeID)
		return nil, false
	}
	return c, true
}

func (s *mfaChallengeStore) IncrAttempts(challengeID string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	if c, ok := s.entries[challengeID]; ok {
		c.Attempts++
		return c.Attempts
	}
	return 0
}

func (s *mfaChallengeStore) Delete(challengeID string) {
	s.mu.Lock()
	delete(s.entries, challengeID)
	s.mu.Unlock()
}
