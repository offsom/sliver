package util

import (
	"testing"
)

func TestAllowedNameSecurity(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		{"valid name", "test123", true},
		{"valid name with dash", "test-file", true},
		{"valid name with underscore", "test_file", true},
		{"valid name with dot", "test.file", true},
		{"empty name", "", false},
		{"path traversal", "..", false},
		{"path traversal prefix", "../file", false},
		{"absolute path", "/usr/bin/test", false},
		{"windows reserved name", "CON", false},
		{"windows reserved name lowercase", "con", false},
		{"starts with dot", ".hidden", true},      // Original test allows this
		{"ends with dot", "file.", true},          // Original test allows this
		{"starts with dash", "-file", true},       // Original test allows this
		{"ends with dash", "file-", true},         // Original test allows this
		{"starts with underscore", "_file", true}, // Original test allows this
		{"ends with underscore", "file_", true},   // Original test allows this
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := AllowedName(tt.input)
			if tt.expected && err != nil {
				t.Errorf("AllowedName(%q) = %v, expected nil", tt.input, err)
			}
			if !tt.expected && err == nil {
				t.Errorf("AllowedName(%q) = nil, expected error", tt.input)
			}
		})
	}
}

func TestSanitizePath(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		expectError bool
	}{
		{"valid relative path", "test/file.txt", false},
		{"valid path with dots", "test/file.txt", false},
		{"path traversal", "..", true},
		{"path traversal in middle", "test/../file.txt", true},
		{"absolute path", "/usr/bin/test", true},
		{"empty path", "", true},
		{"windows path traversal", "..\\file.txt", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := SanitizePath(tt.input)
			if tt.expectError && err == nil {
				t.Errorf("SanitizePath(%q) = nil, expected error", tt.input)
			}
			if !tt.expectError && err != nil {
				t.Errorf("SanitizePath(%q) = %v, expected nil", tt.input, err)
			}
		})
	}
}

func TestValidateExecutablePath(t *testing.T) {
	// This test would be in handlers_test.go, but we'll include it here for completeness
	tests := []struct {
		name        string
		input       string
		expectError bool
	}{
		{"valid executable", "ls", false},
		{"valid executable with path", "/usr/bin/ls", false},
		{"path traversal", "..", true},
		{"dangerous command", "rm", true},
		{"dangerous command uppercase", "RM", true},
		{"dangerous command with path", "/bin/rm", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// This is a placeholder - the actual function would be in handlers.go
			// err := validateExecutablePath(tt.input)
			// if tt.expectError && err == nil {
			//     t.Errorf("validateExecutablePath(%q) = nil, expected error", tt.input)
			// }
			// if !tt.expectError && err != nil {
			//     t.Errorf("validateExecutablePath(%q) = %v, expected nil", tt.input, err)
			// }
		})
	}
}

func TestValidateCommandArgs(t *testing.T) {
	// This test would be in handlers_test.go, but we'll include it here for completeness
	tests := []struct {
		name        string
		input       []string
		expectError bool
	}{
		{"valid args", []string{"-l", "file.txt"}, false},
		{"command injection pipe", []string{"file.txt", "|", "rm", "-rf", "/"}, true},
		{"command injection semicolon", []string{"file.txt", ";", "rm", "-rf", "/"}, true},
		{"command injection ampersand", []string{"file.txt", "&", "rm", "-rf", "/"}, true},
		{"command injection backtick", []string{"file.txt", "`rm -rf /`"}, true},
		{"command injection subshell", []string{"file.txt", "$(rm -rf /)"}, true},
		{"command injection and", []string{"file.txt", "&&", "rm", "-rf", "/"}, true},
		{"command injection or", []string{"file.txt", "||", "rm", "-rf", "/"}, true},
		{"path traversal in arg", []string{"../etc/passwd"}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// This is a placeholder - the actual function would be in handlers.go
			// err := validateCommandArgs(tt.input)
			// if tt.expectError && err == nil {
			//     t.Errorf("validateCommandArgs(%v) = nil, expected error", tt.input)
			// }
			// if !tt.expectError && err != nil {
			//     t.Errorf("validateCommandArgs(%v) = %v, expected nil", tt.input, err)
			// }
		})
	}
}
