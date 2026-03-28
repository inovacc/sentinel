package sandbox

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func newTestSandbox(t *testing.T, readPatterns, execAllow, blocked []string) *Sandbox {
	t.Helper()

	root := filepath.Join(t.TempDir(), "sandbox")
	s, err := New(Config{
		Root:            root,
		ReadPatterns:    readPatterns,
		ExecAllowlist:   execAllow,
		BlockedCommands: blocked,
	})
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	return s
}

// ---------- CheckRead ----------

func TestCheckRead(t *testing.T) {
	s := newTestSandbox(t, []string{"*.log", "*.conf"}, nil, nil)

	// Create a file inside sandbox for testing.
	inner := filepath.Join(s.Root(), "data.txt")
	if err := os.WriteFile(inner, []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		path    string
		wantErr bool
	}{
		{
			name:    "allowed: file inside sandbox",
			path:    inner,
			wantErr: false,
		},
		{
			name:    "allowed: relative path inside sandbox",
			path:    "data.txt",
			wantErr: false,
		},
		{
			name:    "denied: outside sandbox no pattern match",
			path:    filepath.Join(t.TempDir(), "outside.txt"),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := s.CheckRead(tt.path)
			if (err != nil) != tt.wantErr {
				t.Errorf("CheckRead(%q) error = %v, wantErr %v", tt.path, err, tt.wantErr)
			}
		})
	}
}

func TestCheckReadMatchesPattern(t *testing.T) {
	s := newTestSandbox(t, []string{"*.log"}, nil, nil)

	// matchesAnyPattern checks against the base name too, so a .log file
	// should be readable regardless of location.
	logFile := filepath.Join(t.TempDir(), "app.log")
	if err := os.WriteFile(logFile, []byte("log"), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := s.CheckRead(logFile); err != nil {
		t.Errorf("CheckRead(%q) should be allowed by pattern *.log: %v", logFile, err)
	}
}

// ---------- CheckWrite ----------

func TestCheckWrite(t *testing.T) {
	s := newTestSandbox(t, nil, nil, nil)

	tests := []struct {
		name    string
		path    string
		wantErr bool
	}{
		{
			name:    "allowed: inside sandbox",
			path:    filepath.Join(s.Root(), "output.txt"),
			wantErr: false,
		},
		{
			name:    "allowed: relative path",
			path:    "subdir/file.txt",
			wantErr: false,
		},
		{
			name:    "denied: outside sandbox",
			path:    filepath.Join(t.TempDir(), "evil.txt"),
			wantErr: true,
		},
		{
			name:    "denied: traversal attempt",
			path:    filepath.Join(s.Root(), "..", "..", "etc", "passwd"),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := s.CheckWrite(tt.path)
			if (err != nil) != tt.wantErr {
				t.Errorf("CheckWrite(%q) error = %v, wantErr %v", tt.path, err, tt.wantErr)
			}
		})
	}
}

// ---------- CheckDelete ----------

func TestCheckDelete(t *testing.T) {
	s := newTestSandbox(t, nil, nil, nil)

	inner := filepath.Join(s.Root(), "deleteme.txt")
	if err := os.WriteFile(inner, []byte("bye"), 0o644); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		path    string
		wantErr bool
		errIs   error
	}{
		{
			name:    "allowed: file inside sandbox",
			path:    inner,
			wantErr: false,
		},
		{
			name:    "denied: sandbox root itself",
			path:    s.Root(),
			wantErr: true,
			errIs:   ErrDeleteRoot,
		},
		{
			name:    "denied: outside sandbox",
			path:    filepath.Join(t.TempDir(), "important.dat"),
			wantErr: true,
			errIs:   ErrAccessDenied,
		},
		{
			name:    "denied: traversal",
			path:    s.Root() + "/../../etc",
			wantErr: true,
			errIs:   ErrPathTraversal,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := s.CheckDelete(tt.path)
			if (err != nil) != tt.wantErr {
				t.Errorf("CheckDelete(%q) error = %v, wantErr %v", tt.path, err, tt.wantErr)
			}
			if tt.errIs != nil && err != nil {
				if !errors.Is(err, tt.errIs) {
					t.Errorf("CheckDelete(%q) error = %v, want errors.Is %v", tt.path, err, tt.errIs)
				}
			}
		})
	}
}

// ---------- CheckExec ----------

func TestCheckExec(t *testing.T) {
	s := newTestSandbox(t,
		nil,
		[]string{"go", "git", "npm"},
		[]string{"rm -rf /", "format c:"},
	)

	tests := []struct {
		name    string
		cmd     string
		args    []string
		wantErr bool
		errIs   error
	}{
		{
			name:    "allowed: go",
			cmd:     "go",
			args:    []string{"build", "./..."},
			wantErr: false,
		},
		{
			name:    "allowed: git",
			cmd:     "git",
			args:    []string{"status"},
			wantErr: false,
		},
		{
			name:    "denied: not in allowlist",
			cmd:     "curl",
			args:    nil,
			wantErr: true,
			errIs:   ErrExecNotAllowed,
		},
		{
			name:    "denied: path-based command",
			cmd:     "/usr/bin/evil",
			args:    nil,
			wantErr: true,
			errIs:   ErrAbsoluteExec,
		},
		{
			name:    "denied: blocked command pattern",
			cmd:     "rm",
			args:    []string{"-rf", "/"},
			wantErr: true,
			errIs:   ErrBlockedCommand,
		},
		{
			name:    "denied: blocked command exact match",
			cmd:     "format c:",
			args:    nil,
			wantErr: true,
			errIs:   ErrBlockedCommand,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := s.CheckExec(tt.cmd, tt.args)
			if (err != nil) != tt.wantErr {
				t.Errorf("CheckExec(%q, %v) error = %v, wantErr %v", tt.cmd, tt.args, err, tt.wantErr)
			}
			if tt.errIs != nil && err != nil {
				if !errors.Is(err, tt.errIs) {
					t.Errorf("CheckExec(%q, %v) error = %v, want errors.Is %v", tt.cmd, tt.args, err, tt.errIs)
				}
			}
		})
	}
}

// ---------- ResolvePath ----------

func TestResolvePath(t *testing.T) {
	s := newTestSandbox(t, nil, nil, nil)

	tests := []struct {
		name    string
		path    string
		wantErr bool
	}{
		{
			name:    "relative path resolves against root",
			path:    "subdir/file.txt",
			wantErr: false,
		},
		{
			name:    "absolute path is kept",
			path:    filepath.Join(s.Root(), "abs.txt"),
			wantErr: false,
		},
		{
			name:    "empty path",
			path:    "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resolved, err := s.ResolvePath(tt.path)
			if (err != nil) != tt.wantErr {
				t.Errorf("ResolvePath(%q) error = %v, wantErr %v", tt.path, err, tt.wantErr)
			}
			if err == nil && !filepath.IsAbs(resolved) {
				t.Errorf("ResolvePath(%q) = %q, want absolute path", tt.path, resolved)
			}
		})
	}
}

func TestResolvePathRelative(t *testing.T) {
	s := newTestSandbox(t, nil, nil, nil)

	resolved, err := s.ResolvePath("subdir/file.txt")
	if err != nil {
		t.Fatal(err)
	}

	expected := filepath.Join(s.Root(), "subdir", "file.txt")
	if resolved != expected {
		t.Errorf("ResolvePath relative = %q, want %q", resolved, expected)
	}
}

// ---------- SandboxPath ----------

func TestSandboxPath(t *testing.T) {
	s := newTestSandbox(t, nil, nil, nil)

	got := s.SandboxPath("sub/file.txt")
	want := filepath.Join(s.Root(), "sub", "file.txt")
	if got != want {
		t.Errorf("SandboxPath() = %q, want %q", got, want)
	}
}

// ---------- isSubPath ----------

func TestIsSubPath(t *testing.T) {
	root := t.TempDir()
	child := filepath.Join(root, "a", "b")
	if err := os.MkdirAll(child, 0o755); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name   string
		parent string
		child  string
		want   bool
	}{
		{"direct child", root, filepath.Join(root, "a"), true},
		{"nested child", root, child, true},
		{"same path", root, root, true},
		{"outside", root, t.TempDir(), false},
		{"similar prefix", root, root + "-extra", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isSubPath(tt.parent, tt.child); got != tt.want {
				t.Errorf("isSubPath(%q, %q) = %v, want %v", tt.parent, tt.child, got, tt.want)
			}
		})
	}
}

// ---------- Symlink tests ----------

func TestSymlinkEscape(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink tests require elevated privileges on Windows")
	}

	s := newTestSandbox(t, nil, nil, nil)

	// Create a directory outside the sandbox.
	outsideDir := t.TempDir()
	outsideFile := filepath.Join(outsideDir, "secret.txt")
	if err := os.WriteFile(outsideFile, []byte("secret"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Create a symlink inside sandbox pointing outside.
	link := filepath.Join(s.Root(), "escape-link")
	if err := os.Symlink(outsideDir, link); err != nil {
		t.Skipf("cannot create symlink: %v", err)
	}

	// Write to symlinked path should be denied.
	target := filepath.Join(link, "secret.txt")
	if err := s.CheckWrite(target); err == nil {
		t.Error("CheckWrite through symlink escape should be denied")
	}

	// Delete through symlink escape should be denied.
	if err := s.CheckDelete(target); err == nil {
		t.Error("CheckDelete through symlink escape should be denied")
	}
}

// ---------- Path traversal attacks ----------

func TestPathTraversalAttacks(t *testing.T) {
	s := newTestSandbox(t, nil, nil, nil)

	attacks := []string{
		"../../etc/passwd",
		"../../../etc/shadow",
		"sandbox/../../../etc/hosts",
		"./../../outside",
	}

	for _, attack := range attacks {
		t.Run("write_"+attack, func(t *testing.T) {
			if err := s.CheckWrite(attack); err == nil {
				t.Errorf("CheckWrite(%q) should be denied", attack)
			}
		})
		t.Run("delete_"+attack, func(t *testing.T) {
			if err := s.CheckDelete(attack); err == nil {
				t.Errorf("CheckDelete(%q) should be denied", attack)
			}
		})
	}
}

// ---------- Windows-specific path tests ----------

func TestWindowsPaths(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows-specific test")
	}

	s := newTestSandbox(t, nil, nil, nil)

	// Write inside sandbox should work with Windows paths.
	winPath := filepath.Join(s.Root(), "subdir", "file.txt")
	if err := s.CheckWrite(winPath); err != nil {
		t.Errorf("CheckWrite(%q) should be allowed: %v", winPath, err)
	}

	// Backslash-based traversal on Windows.
	attack := s.Root() + `\..\..\Windows\System32\config`
	if err := s.CheckWrite(attack); err == nil {
		t.Errorf("CheckWrite(%q) should be denied", attack)
	}
}

// ---------- containsTraversal ----------

func TestContainsTraversal(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{"safe/path/file.txt", false},
		{"../escape", true},
		{"a/../../b", true},
		{"a/b/c", false},
		{".hidden/file", false},
		{"...", false},
		{"..", true},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			if got := containsTraversal(tt.path); got != tt.want {
				t.Errorf("containsTraversal(%q) = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}

// ---------- matchesAnyPattern ----------

func TestMatchesAnyPattern(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		patterns []string
		want     bool
	}{
		{"match log extension", "/var/log/app.log", []string{"*.log"}, true},
		{"no match", "/var/data/app.db", []string{"*.log", "*.conf"}, false},
		{"match conf", "nginx.conf", []string{"*.conf"}, true},
		{"empty patterns", "file.txt", nil, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := matchesAnyPattern(tt.path, tt.patterns); got != tt.want {
				t.Errorf("matchesAnyPattern(%q, %v) = %v, want %v", tt.path, tt.patterns, got, tt.want)
			}
		})
	}
}

// ---------- isBlockedCommand ----------

func TestIsBlockedCommand(t *testing.T) {
	blocked := []string{"rm -rf /", "format c:", "dd if="}

	tests := []struct {
		name string
		cmd  string
		args []string
		want bool
	}{
		{"blocked rm -rf /", "rm", []string{"-rf", "/"}, true},
		{"blocked format", "format c:", nil, true},
		{"blocked dd", "dd", []string{"if=/dev/zero", "of=/dev/sda"}, true},
		{"safe ls", "ls", []string{"-la"}, false},
		{"safe git", "git", []string{"status"}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isBlockedCommand(tt.cmd, tt.args, blocked); got != tt.want {
				t.Errorf("isBlockedCommand(%q, %v) = %v, want %v", tt.cmd, tt.args, got, tt.want)
			}
		})
	}
}

// ---------- sanitizePath ----------

func TestSanitizePath(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"a/b/../c", filepath.Clean("a/b/../c")},
		{"./file.txt", filepath.Clean("./file.txt")},
		{"a//b///c", filepath.Clean("a//b///c")},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			if got := sanitizePath(tt.input); got != tt.want {
				t.Errorf("sanitizePath(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

// ---------- New() validation ----------

func TestNewEmptyRoot(t *testing.T) {
	_, err := New(Config{Root: ""})
	if err == nil {
		t.Error("New with empty root should return error")
	}
}

func TestNewCreatesDirectory(t *testing.T) {
	root := filepath.Join(t.TempDir(), "new-sandbox")
	s, err := New(Config{Root: root})
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	info, err := os.Stat(s.Root())
	if err != nil {
		t.Fatalf("sandbox root not created: %v", err)
	}
	if !info.IsDir() {
		t.Error("sandbox root is not a directory")
	}
}

// ---------- CheckExec with path separator ----------

func TestCheckExecRejectsPathSeparator(t *testing.T) {
	s := newTestSandbox(t, nil, []string{"go"}, nil)

	cmds := []string{
		"/usr/bin/go",
		"./go",
		"../go",
	}

	if runtime.GOOS == "windows" {
		cmds = append(cmds, `C:\Go\bin\go.exe`, `..\go`)
	}

	for _, cmd := range cmds {
		t.Run(cmd, func(t *testing.T) {
			err := s.CheckExec(cmd, nil)
			if !errors.Is(err, ErrAbsoluteExec) {
				t.Errorf("CheckExec(%q) = %v, want ErrAbsoluteExec", cmd, err)
			}
		})
	}
}
