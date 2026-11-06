package reminders

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// Reminder describes a persisted date reminder.
type Reminder struct {
	ID         string     `json:"id"`
	Title      string     `json:"title"`
	Content    string     `json:"content"`
	RemindAt   time.Time  `json:"remindAt"`
	Done       bool       `json:"done"`
	NotifiedAt *time.Time `json:"notifiedAt,omitempty"`
	CreatedAt  time.Time  `json:"createdAt"`
}

// Store persists reminders to static/data/reminders.json.
type Store struct {
	path  string
	mu    sync.Mutex
	items []Reminder
}

func NewStore(path string) (*Store, error) {
	store := &Store{path: path, items: []Reminder{}}
	return store, store.load()
}

func (s *Store) List(includeDone bool) []Reminder {
	s.mu.Lock()
	defer s.mu.Unlock()

	out := make([]Reminder, 0, len(s.items))
	for _, item := range s.items {
		if includeDone || !item.Done {
			out = append(out, item)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		return out[i].RemindAt.Before(out[j].RemindAt)
	})
	return out
}

func (s *Store) Due(now time.Time) []Reminder {
	s.mu.Lock()
	defer s.mu.Unlock()

	var out []Reminder
	for _, item := range s.items {
		if !item.Done && item.NotifiedAt == nil && !item.RemindAt.After(now) {
			out = append(out, item)
		}
	}
	return out
}

func (s *Store) Add(title string, content string, remindAt time.Time) (Reminder, error) {
	item := Reminder{
		ID:        newID(),
		Title:     title,
		Content:   content,
		RemindAt:  remindAt,
		Done:      false,
		CreatedAt: time.Now(),
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.items = append(s.items, item)
	return item, s.saveLocked()
}

func (s *Store) SetDone(id string, done bool) (Reminder, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for i := range s.items {
		if s.items[i].ID == id {
			s.items[i].Done = done
			return s.items[i], s.saveLocked()
		}
	}
	return Reminder{}, errors.New("reminder not found")
}

func (s *Store) MarkNotified(id string, notifiedAt time.Time) (Reminder, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for i := range s.items {
		if s.items[i].ID == id {
			s.items[i].NotifiedAt = &notifiedAt
			return s.items[i], s.saveLocked()
		}
	}
	return Reminder{}, errors.New("reminder not found")
}

func (s *Store) Delete(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for i := range s.items {
		if s.items[i].ID == id {
			s.items = append(s.items[:i], s.items[i+1:]...)
			return s.saveLocked()
		}
	}
	return errors.New("reminder not found")
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
