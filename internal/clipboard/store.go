package clipboard

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// maxItems caps the shared clipboard history so the persisted file stays small.
const maxItems = 100

// Clip is one shared clipboard entry broadcast through /ws and stored on disk.
type Clip struct {
	ID      string    `json:"id"`
	Content string    `json:"content"`
	Time    time.Time `json:"time"`
}

// Store keeps shared clipboard history in memory and persists it to static/data/clipboard.json.
type Store struct {
	path  string
	mu    sync.Mutex
	items []Clip
}

func NewStore(path string) (*Store, error) {
	store := &Store{path: path, items: []Clip{}}
	return store, store.load()
}

// List returns clipboard history in chronological order (oldest first).
func (s *Store) List() []Clip {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Clip, len(s.items))
	copy(out, s.items)
	return out
}

// Add appends a clip and trims the oldest entries beyond maxItems.
func (s *Store) Add(content string) (Clip, error) {
	item := Clip{ID: newID(), Content: content, Time: time.Now()}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.items = append(s.items, item)
	if len(s.items) > maxItems {
		s.items = s.items[len(s.items)-maxItems:]
	}
	return item, s.saveLocked()
}

// Delete removes one clip by id.
func (s *Store) Delete(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for i := range s.items {
		if s.items[i].ID == id {
			s.items = append(s.items[:i], s.items[i+1:]...)
			return s.saveLocked()
		}
	}
	return errors.New("clip not found")
}

// Clear removes all clipboard history.
func (s *Store) Clear() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.items = []Clip{}
	return s.saveLocked()
}

func (s *Store) load() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	data, err := os.ReadFile(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	return json.Unmarshal(data, &s.items)
}

func (s *Store) saveLocked() error {
	if err := os.MkdirAll(filepath.Dir(s.path), os.ModePerm); err != nil {
		return err
	}
	data, err := json.MarshalIndent(s.items, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.path, data, 0644)
}

func newID() string {
	buf := make([]byte, 8)
	if _, err := rand.Read(buf); err != nil {
		return hex.EncodeToString([]byte(time.Now().Format("20060102150405.000000000")))
	}
	return hex.EncodeToString(buf)
}
