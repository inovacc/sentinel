package fs

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/inovacc/sentinel/internal/sandbox"
)

// newTestService creates a sandbox rooted at t.TempDir() and returns the Service.
func newTestService(t *testing.T) (*Service, string) {
	t.Helper()
	root := t.TempDir()
	sb, err := sandbox.New(sandbox.Config{Root: root})
	if err != nil {
		t.Fatalf("create sandbox: %v", err)
	}
	return NewService(sb), root
}

func TestReadFile(t *testing.T) {
	tests := []struct {
		name    string
		setup   func(root string) string // returns path to read
		offset  int64
		limit   int64
		wantErr bool
		check   func(t *testing.T, content []byte, size int64, mimeType string)
	}{
		{
			name: "read file in sandbox",
			setup: func(root string) string {
				p := filepath.Join(root, "hello.txt")
				if err := os.WriteFile(p, []byte("hello world"), 0o644); err != nil {
					t.Fatal(err)
				}
				return p
			},
			wantErr: false,
			check: func(t *testing.T, content []byte, size int64, mimeType string) {
				if string(content) != "hello world" {
					t.Errorf("content = %q, want %q", content, "hello world")
				}
				if size != 11 {
					t.Errorf("size = %d, want 11", size)
				}
				if mimeType != "text/plain" {
					t.Errorf("mimeType = %q, want text/plain", mimeType)
				}
			},
		},
		{
			name: "read file outside sandbox denied",
			setup: func(_ string) string {
				// Create a temp file outside the sandbox root.
				tmp := t.TempDir()
				p := filepath.Join(tmp, "outside.txt")
				if err := os.WriteFile(p, []byte("secret"), 0o644); err != nil {
					t.Fatal(err)
				}
				return p
			},
			wantErr: true,
		},
		{
			name: "read file with offset and limit",
			setup: func(root string) string {
				p := filepath.Join(root, "data.json")
				if err := os.WriteFile(p, []byte("0123456789"), 0o644); err != nil {
					t.Fatal(err)
				}
				return p
			},
			offset:  3,
			limit:   4,
			wantErr: false,
			check: func(t *testing.T, content []byte, size int64, mimeType string) {
				if string(content) != "3456" {
					t.Errorf("content = %q, want %q", content, "3456")
				}
				if size != 10 {
					t.Errorf("size = %d, want 10", size)
				}
				if mimeType != "application/json" {
					t.Errorf("mimeType = %q, want application/json", mimeType)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc, root := newTestService(t)
			path := tt.setup(root)
			content, size, mimeType, err := svc.ReadFile(path, tt.offset, tt.limit)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ReadFile() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr && tt.check != nil {
				tt.check(t, content, size, mimeType)
			}
		})
	}
}

func TestWriteFile(t *testing.T) {
	tests := []struct {
		name       string
		path       string // relative to root
		content    []byte
		createDirs bool
		wantErr    bool
	}{
		{
			name:    "write file in sandbox",
			path:    "output.txt",
			content: []byte("written content"),
			wantErr: false,
		},
		{
			name:       "write file with create dirs",
			path:       "sub/dir/file.txt",
			content:    []byte("nested"),
			createDirs: true,
			wantErr:    false,
		},
		{
			name:    "write file outside sandbox denied",
			path:    "", // will be set to outside path
			content: []byte("bad"),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc, root := newTestService(t)
			var path string
			if tt.name == "write file outside sandbox denied" {
				outsideDir := t.TempDir()
				path = filepath.Join(outsideDir, "outside.txt")
			} else {
				path = filepath.Join(root, tt.path)
			}

			written, err := svc.WriteFile(path, tt.content, tt.createDirs)
			if (err != nil) != tt.wantErr {
				t.Fatalf("WriteFile() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr {
				if written != int64(len(tt.content)) {
					t.Errorf("written = %d, want %d", written, len(tt.content))
				}
				data, readErr := os.ReadFile(path)
				if readErr != nil {
					t.Fatalf("read back: %v", readErr)
				}
				if string(data) != string(tt.content) {
					t.Errorf("read back = %q, want %q", data, tt.content)
				}
			}
		})
	}
}

func TestListDir(t *testing.T) {
	tests := []struct {
		name      string
		recursive bool
		setup     func(root string)
		wantCount int
		wantErr   bool
	}{
		{
			name:      "non-recursive list",
			recursive: false,
			setup: func(root string) {
				_ = os.WriteFile(filepath.Join(root, "a.txt"), []byte("a"), 0o644)
				_ = os.WriteFile(filepath.Join(root, "b.txt"), []byte("b"), 0o644)
				_ = os.MkdirAll(filepath.Join(root, "subdir"), 0o750)
			},
			wantCount: 3, // a.txt, b.txt, subdir
		},
		{
			name:      "recursive list",
			recursive: true,
			setup: func(root string) {
				_ = os.WriteFile(filepath.Join(root, "a.txt"), []byte("a"), 0o644)
				_ = os.MkdirAll(filepath.Join(root, "sub"), 0o750)
				_ = os.WriteFile(filepath.Join(root, "sub", "c.txt"), []byte("c"), 0o644)
			},
			wantCount: 3, // a.txt, sub, sub/c.txt
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc, root := newTestService(t)
			tt.setup(root)
			entries, err := svc.ListDir(root, tt.recursive)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ListDir() error = %v, wantErr %v", err, tt.wantErr)
			}
			if len(entries) != tt.wantCount {
				t.Errorf("got %d entries, want %d", len(entries), tt.wantCount)
				for _, e := range entries {
					t.Logf("  entry: %s (dir=%v)", e.Path, e.IsDir)
				}
			}
		})
	}
}

func TestDeleteFile(t *testing.T) {
	tests := []struct {
		name    string
		setup   func(root string) string
		wantErr bool
	}{
		{
			name: "delete file in sandbox",
			setup: func(root string) string {
				p := filepath.Join(root, "delete-me.txt")
				_ = os.WriteFile(p, []byte("bye"), 0o644)
				return p
			},
			wantErr: false,
		},
		{
			name: "delete file outside sandbox denied",
			setup: func(_ string) string {
				tmp := t.TempDir()
				p := filepath.Join(tmp, "outside.txt")
				_ = os.WriteFile(p, []byte("no"), 0o644)
				return p
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc, root := newTestService(t)
			path := tt.setup(root)
			err := svc.DeleteFile(path)
			if (err != nil) != tt.wantErr {
				t.Fatalf("DeleteFile() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr {
				if _, statErr := os.Stat(path); !os.IsNotExist(statErr) {
					t.Error("file still exists after delete")
				}
			}
		})
	}
}

func TestGlob(t *testing.T) {
	tests := []struct {
		name      string
		pattern   string
		setup     func(root string)
		wantCount int
		wantErr   bool
	}{
		{
			name:    "glob txt files",
			pattern: "*.txt",
			setup: func(root string) {
				_ = os.WriteFile(filepath.Join(root, "a.txt"), []byte("a"), 0o644)
				_ = os.WriteFile(filepath.Join(root, "b.txt"), []byte("b"), 0o644)
				_ = os.WriteFile(filepath.Join(root, "c.go"), []byte("c"), 0o644)
			},
			wantCount: 2,
		},
		{
			name:    "glob no matches",
			pattern: "*.rs",
			setup: func(root string) {
				_ = os.WriteFile(filepath.Join(root, "a.txt"), []byte("a"), 0o644)
			},
			wantCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc, root := newTestService(t)
			tt.setup(root)
			matches, err := svc.Glob(tt.pattern, root)
			if (err != nil) != tt.wantErr {
				t.Fatalf("Glob() error = %v, wantErr %v", err, tt.wantErr)
			}
			if len(matches) != tt.wantCount {
				t.Errorf("got %d matches, want %d: %v", len(matches), tt.wantCount, matches)
			}
		})
	}
}

func TestGrep(t *testing.T) {
	tests := []struct {
		name         string
		pattern      string
		recursive    bool
		ignoreCase   bool
		contextLines int
		setup        func(root string) string // returns path to search
		wantCount    int
		wantErr      bool
		check        func(t *testing.T, matches []GrepMatch)
	}{
		{
			name:    "grep single file",
			pattern: "hello",
			setup: func(root string) string {
				p := filepath.Join(root, "test.txt")
				_ = os.WriteFile(p, []byte("hello world\ngoodbye\nhello again"), 0o644)
				return p
			},
			wantCount: 2,
		},
		{
			name:       "grep ignore case",
			pattern:    "hello",
			ignoreCase: true,
			setup: func(root string) string {
				p := filepath.Join(root, "test.txt")
				_ = os.WriteFile(p, []byte("Hello World\nhello\nGoodbye"), 0o644)
				return p
			},
			wantCount: 2,
		},
		{
			name:         "grep with context lines",
			pattern:      "match",
			contextLines: 1,
			setup: func(root string) string {
				p := filepath.Join(root, "ctx.txt")
				_ = os.WriteFile(p, []byte("before\nmatch line\nafter"), 0o644)
				return p
			},
			wantCount: 1,
			check: func(t *testing.T, matches []GrepMatch) {
				m := matches[0]
				if len(m.ContextBefore) != 1 || m.ContextBefore[0] != "before" {
					t.Errorf("context before = %v, want [before]", m.ContextBefore)
				}
				if len(m.ContextAfter) != 1 || m.ContextAfter[0] != "after" {
					t.Errorf("context after = %v, want [after]", m.ContextAfter)
				}
				if m.Line != 2 {
					t.Errorf("line = %d, want 2", m.Line)
				}
			},
		},
		{
			name:      "grep recursive directory",
			pattern:   "needle",
			recursive: true,
			setup: func(root string) string {
				_ = os.MkdirAll(filepath.Join(root, "sub"), 0o750)
				_ = os.WriteFile(filepath.Join(root, "a.txt"), []byte("needle here"), 0o644)
				_ = os.WriteFile(filepath.Join(root, "sub", "b.txt"), []byte("also needle"), 0o644)
				_ = os.WriteFile(filepath.Join(root, "c.txt"), []byte("no match"), 0o644)
				return root
			},
			wantCount: 2,
		},
		{
			name:    "grep regex pattern",
			pattern: `func\s+\w+`,
			setup: func(root string) string {
				p := filepath.Join(root, "code.go")
				_ = os.WriteFile(p, []byte("func main() {\n\tx := 1\n}\nfunc helper() {\n}"), 0o644)
				return p
			},
			wantCount: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc, root := newTestService(t)
			path := tt.setup(root)
			matches, err := svc.Grep(tt.pattern, path, tt.recursive, tt.ignoreCase, tt.contextLines)
			if (err != nil) != tt.wantErr {
				t.Fatalf("Grep() error = %v, wantErr %v", err, tt.wantErr)
			}
			if len(matches) != tt.wantCount {
				t.Errorf("got %d matches, want %d", len(matches), tt.wantCount)
				for _, m := range matches {
					t.Logf("  match: %s:%d %q", m.File, m.Line, m.Text)
				}
			}
			if tt.check != nil {
				tt.check(t, matches)
			}
		})
	}
}

func TestDetectMIME(t *testing.T) {
	tests := []struct {
		path string
		want string
	}{
		{"file.go", "text/x-go"},
		{"file.json", "application/json"},
		{"file.py", "text/x-python"},
		{"file.txt", "text/plain"},
		{"file.rs", "text/x-rust"},
		{"file.unknown", "application/octet-stream"},
		{"file", "application/octet-stream"},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			got := detectMIME(tt.path)
			if got != tt.want {
				t.Errorf("detectMIME(%q) = %q, want %q", tt.path, got, tt.want)
			}
		})
	}
}
