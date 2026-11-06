package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"BackEnd/internal/storage"

	tea "github.com/charmbracelet/bubbletea"
)

const (
	colorReset  = "\033[0m"
	colorCyan   = "\033[36m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorDim    = "\033[2m"
)

var commands = []string{"/images", "/files", "/videos", "/audios", "/help", "/quit"}

type model struct {
	staticRoot string
	input      string
	output     []string
	err        error
}

// Run starts a Bubble Tea command UI for browsing static assets.
func Run(staticRoot string) error {
	initial := model{
		staticRoot: staticRoot,
		output: []string{
			colorCyan + "Static Store CLI" + colorReset,
			colorDim + "Commands: /images, /files, /videos, /audios, /help, /quit. Press Tab for completion." + colorReset,
		},
	}
	_, err := tea.NewProgram(initial).Run()
	return err
}

func (m model) Init() tea.Cmd {
	return nil
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.Type {
		case tea.KeyCtrlC, tea.KeyEsc:
			return m, tea.Quit
		case tea.KeyEnter:
			next, quit := m.runCommand(strings.TrimSpace(m.input))
			next.input = ""
			if quit {
				return next, tea.Quit
			}
			return next, nil
		case tea.KeyBackspace:
			if len(m.input) > 0 {
				m.input = m.input[:len(m.input)-1]
			}
			return m, nil
		case tea.KeyTab:
			m.applyCompletion()
			return m, nil
		default:
			m.input += msg.String()
			return m, nil
		}
	}
	return m, nil
}

func (m model) View() string {
	lines := append([]string{}, m.output...)
	lines = append(lines, "")
	lines = append(lines, colorGreen+"store> "+colorReset+m.input)
	return strings.Join(lines, "\n")
}

func (m model) runCommand(line string) (model, bool) {
	if line == "" {
		return m, false
	}
	m.output = appendOutput(m.output, colorGreen+"store> "+colorReset+line)

	parts := strings.Fields(line)
	switch parts[0] {
	case "/images":
		m.output = append(m.output, listDir(filepath.Join(m.staticRoot, "images"), "image")...)
	case "/files":
		m.output = append(m.output, listDir(filepath.Join(m.staticRoot, "files"), "file")...)
	case "/videos":
		m.output = append(m.output, listDir(filepath.Join(m.staticRoot, "files"), "video")...)
	case "/audios":
		m.output = append(m.output, listDir(filepath.Join(m.staticRoot, "files"), "audio")...)
	case "/help":
		m.output = append(m.output, helpLines()...)
	case "/quit":
		return m, true
	default:
		m.output = append(m.output, colorYellow+"Unknown command. Try /help."+colorReset)
	}
	return m, false
}

func (m *model) applyCompletion() {
	prefix := strings.TrimSpace(m.input)
	if prefix == "" {
		m.output = appendOutput(m.output, strings.Join(commands, "  "))
		return
	}

	if strings.Contains(prefix, " ") {
		m.output = appendOutput(m.output, fileCompletions(m.staticRoot, prefix)...)
		return
	}

	matches := matchingCommands(prefix)
	if len(matches) == 1 {
		m.input = matches[0]
		return
	}
	if len(matches) > 1 {
		m.output = appendOutput(m.output, strings.Join(matches, "  "))
	}
}

func helpLines() []string {
	return []string{
		"/images  list static/images",
		"/files   list non-video/non-audio files in static/files",
		"/videos  list mp4/webm/ogv/mov/mkv videos in static/files",
		"/audios  list mp3/wav/flac/aac/m4a/ogg/opus audio in static/files",
		"/quit    exit CLI",
	}
}

func matchingCommands(prefix string) []string {
	var matches []string
	for _, command := range commands {
		if strings.HasPrefix(command, prefix) {
			matches = append(matches, command)
		}
	}
	return matches
}

func listDir(dir string, category string) []string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return []string{colorYellow + "Cannot read directory: " + colorReset + err.Error()}
	}

	var rows []string
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		itemCategory := storage.CategoryForExt(filepath.Ext(entry.Name()))
		if !matchesCategory(category, itemCategory) {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			continue
		}
		rows = append(rows, formatRow(entry.Name(), itemCategory, info.Size(), info.ModTime()))
	}

	sort.Strings(rows)
	if len(rows) == 0 {
		return []string{colorDim + "No items." + colorReset}
	}
	return rows
}

func fileCompletions(staticRoot string, input string) []string {
	parts := strings.Fields(input)
	if len(parts) == 0 {
		return nil
	}

	dir := filepath.Join(staticRoot, "files")
	category := "file"
	switch parts[0] {
	case "/images":
		dir = filepath.Join(staticRoot, "images")
		category = "image"
	case "/videos":
		category = "video"
	case "/audios":
		category = "audio"
	case "/files":
		category = "file"
	default:
		return nil
	}

	prefix := ""
	if len(parts) > 1 {
		prefix = parts[1]
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		return []string{colorYellow + "Cannot read directory: " + colorReset + err.Error()}
	}

	var matches []string
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasPrefix(entry.Name(), prefix) {
			continue
		}
		itemCategory := storage.CategoryForExt(filepath.Ext(entry.Name()))
		if matchesCategory(category, itemCategory) {
			matches = append(matches, colorCyan+entry.Name()+colorReset)
		}
	}
	if len(matches) == 0 {
		return []string{colorDim + "No completions." + colorReset}
	}
	sort.Strings(matches)
	return matches
}

func matchesCategory(want string, actual string) bool {
	switch want {
	case "image":
		return actual == "image"
	case "video":
		return actual == "video"
	case "audio":
		return actual == "audio"
	case "file":
		return actual != "image" && actual != "video" && actual != "audio"
	default:
		return true
	}
}

func appendOutput(output []string, lines ...string) []string {
	output = append(output, lines...)
	if len(output) > 80 {
		return output[len(output)-80:]
	}
	return output
}

func formatRow(name string, category string, size int64, modTime time.Time) string {
	return fmt.Sprintf("%s%-9s%s %10s  %s  %s", colorCyan, category, colorReset, humanSize(size), modTime.Format("2006-01-02 15:04"), name)
}

func humanSize(size int64) string {
	units := []string{"B", "KB", "MB", "GB"}
	value := float64(size)
	unit := 0
	for value >= 1024 && unit < len(units)-1 {
		value /= 1024
		unit++
	}
	if unit == 0 {
		return fmt.Sprintf("%d%s", size, units[unit])
	}
	return fmt.Sprintf("%.1f%s", value, units[unit])
}
