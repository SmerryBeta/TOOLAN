package messages

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Message is the persisted message shape shared by /message, /notify and /ws.
type Message struct {
	Title   string    `json:"title"`
	Content string    `json:"content"`
	Time    time.Time `json:"time"`
}

// Store keeps messages in memory and persists them to static/data/messages.json.
type Store struct {
	path  string
	mu    sync.Mutex
	items []Message
}

func NewStore(path string) (*Store, error) {
	store := &Store{path: path, items: []Message{}}
	return store, store.load()
}

func (s *Store) List() []Message {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Message, len(s.items))
	copy(out, s.items)
	return out
}

func (s *Store) Add(title string, content string) (Message, error) {
	msg := Message{Title: title, Content: content, Time: time.Now()}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.items = append(s.items, msg)
	return msg, s.saveLocked()
}

func (s *Store) Delete(index int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if index < 0 || index >= len(s.items) {
		return errors.New("index out of range")
	}
	s.items = append(s.items[:index], s.items[index+1:]...)
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
