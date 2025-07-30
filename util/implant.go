package util

/*
	Sliver Implant Framework
	Copyright (C) 2019  Bishop Fox

	This program is free software: you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation, either version 3 of the License, or
	(at your option) any later version.

	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

import (
	"errors"
	"path/filepath"
	"regexp"
	"strings"
)

// AllowedName - Validate and sanitize file/directory names
func AllowedName(name string) error {
	if name == "" {
		return errors.New("name cannot be blank")
	}

	// Clean the path to prevent path traversal
	cleanName := filepath.Clean(name)
	if cleanName != name {
		return errors.New("name contains path traversal characters")
	}

	// Check for absolute paths
	if filepath.IsAbs(cleanName) {
		return errors.New("absolute paths are not allowed")
	}

	// Check for parent directory references (but allow double dots in the middle)
	if cleanName == ".." || strings.HasPrefix(cleanName, "..") {
		return errors.New("parent directory references are not allowed")
	}

	// Allow alphanumeric, periods, dashes, and underscores
	isAllowed := regexp.MustCompile(`^[[:alnum:]\.\-_]+$`).MatchString

	if !isAllowed(cleanName) {
		return errors.New("name must be alphanumeric or .-_ only")
	}

	// Additional checks for dangerous patterns
	dangerousPatterns := []string{
		".",
		"..",
		"CON", "PRN", "AUX", "NUL", // Windows reserved names
		"COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
		"LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
	}

	for _, pattern := range dangerousPatterns {
		if strings.EqualFold(cleanName, pattern) {
			return errors.New("name cannot be a reserved system name")
		}
	}

	return nil
}

// SanitizePath - Sanitize and validate file paths
func SanitizePath(path string) (string, error) {
	if path == "" {
		return "", errors.New("path cannot be empty")
	}

	// Check for path traversal attempts in original path
	if strings.Contains(path, "..") {
		return "", errors.New("path traversal not allowed")
	}

	// Clean the path
	cleanPath := filepath.Clean(path)

	// Check for path traversal attempts in cleaned path
	if strings.Contains(cleanPath, "..") {
		return "", errors.New("path traversal not allowed")
	}

	// Check for absolute paths (if not allowed in your context)
	if filepath.IsAbs(cleanPath) {
		return "", errors.New("absolute paths not allowed")
	}

	return cleanPath, nil
}
