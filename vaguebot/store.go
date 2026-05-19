package vaguebot

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

type AccountRecord struct {
	CID          string `json:"cid"`
	Email        string `json:"email,omitempty"`
	Passwd       string `json:"passwd,omitempty"`
	Token        string `json:"token"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Revision     int64  `json:"revision"`
	DeviceID     string `json:"device_id,omitempty"`
	E2EEPublic   string `json:"e2ee_public_key,omitempty"`
	E2EEPrivate  string `json:"e2ee_private_key,omitempty"`
}

type accountFile struct {
	Accounts []AccountRecord `json:"accounts"`
}

type AccountStore struct {
	path string
	mu   sync.Mutex
	data accountFile
}

func NewAccountStore(path string) (*AccountStore, error) {
	if strings := filepath.Clean(path); strings == "." || strings == "" {
		return nil, errors.New("account file path is required")
	}
	store := &AccountStore{path: path}
	if err := store.load(); err != nil {
		return nil, err
	}
	return store, nil
}

func (s *AccountStore) load() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	raw, err := os.ReadFile(s.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			s.data = accountFile{Accounts: []AccountRecord{}}
			return nil
		}
		return fmt.Errorf("read account file: %w", err)
	}
	if len(raw) == 0 {
		s.data = accountFile{Accounts: []AccountRecord{}}
		return nil
	}

	var decoded accountFile
	if err := json.Unmarshal(raw, &decoded); err != nil {
		return fmt.Errorf("parse account file: %w", err)
	}
	if decoded.Accounts == nil {
		decoded.Accounts = []AccountRecord{}
	}
	s.data = decoded
	return nil
}

func (s *AccountStore) Accounts() []AccountRecord {
	s.mu.Lock()
	defer s.mu.Unlock()

	out := make([]AccountRecord, 0, len(s.data.Accounts))
	out = append(out, s.data.Accounts...)
	return out
}

func (s *AccountStore) Upsert(account AccountRecord) error {
	if account.Token == "" && account.CID == "" && account.Email == "" {
		return nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	index := -1
	for i := range s.data.Accounts {
		current := s.data.Accounts[i]
		if account.CID != "" && current.CID == account.CID {
			index = i
			break
		}
	}
	if index < 0 {
		for i := range s.data.Accounts {
			current := s.data.Accounts[i]
			if account.Email != "" && current.Email == account.Email {
				index = i
				break
			}
			if account.Token != "" && current.Token == account.Token {
				index = i
				break
			}
		}
	}

	if index < 0 {
		s.data.Accounts = append(s.data.Accounts, account)
		return s.saveLocked()
	}

	existing := s.data.Accounts[index]
	if account.CID != "" {
		existing.CID = account.CID
	}
	if account.Email != "" {
		existing.Email = account.Email
	}
	if account.Passwd != "" {
		existing.Passwd = account.Passwd
	}
	if account.Token != "" {
		existing.Token = account.Token
	}
	if account.RefreshToken != "" {
		existing.RefreshToken = account.RefreshToken
	}
	if account.Revision > 0 {
		existing.Revision = account.Revision
	}
	if account.DeviceID != "" {
		existing.DeviceID = account.DeviceID
	}
	if account.E2EEPublic != "" {
		existing.E2EEPublic = account.E2EEPublic
	}
	if account.E2EEPrivate != "" {
		existing.E2EEPrivate = account.E2EEPrivate
	}
	s.data.Accounts[index] = existing
	return s.saveLocked()
}

func (s *AccountStore) saveLocked() error {
	dir := filepath.Dir(s.path)
	if dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("create account directory: %w", err)
		}
	}

	raw, err := json.MarshalIndent(s.data, "", "  ")
	if err != nil {
		return fmt.Errorf("encode account file: %w", err)
	}

	tempPath := s.path + ".tmp"
	if err := os.WriteFile(tempPath, raw, 0o600); err != nil {
		return fmt.Errorf("write temp account file: %w", err)
	}
	if err := os.Rename(tempPath, s.path); err != nil {
		return fmt.Errorf("replace account file: %w", err)
	}
	return nil
}
