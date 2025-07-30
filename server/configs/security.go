package configs

/*
	Sliver Implant Framework
	Copyright (C) 2024  Bishop Fox

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
	"time"
)

var ErrInvalidConfig = errors.New("invalid security config")

// SecurityConfig - Security configuration settings
type SecurityConfig struct {
	// Authentication settings
	TokenExpiryMinutes int `json:"token_expiry_minutes"`
	MaxLoginAttempts   int `json:"max_login_attempts"`
	LockoutDuration    int `json:"lockout_duration_minutes"`

	// Session settings
	SessionTimeoutMinutes int `json:"session_timeout_minutes"`
	MaxConcurrentSessions int `json:"max_concurrent_sessions"`

	// Input validation settings
	MaxCommandLength      int      `json:"max_command_length"`
	MaxFilePathLength     int      `json:"max_file_path_length"`
	AllowedFileExtensions []string `json:"allowed_file_extensions"`

	// Network security settings
	AllowedIPRanges    []string `json:"allowed_ip_ranges"`
	RequireHTTPS       bool     `json:"require_https"`
	EnableRateLimiting bool     `json:"enable_rate_limiting"`
	RateLimitRequests  int      `json:"rate_limit_requests_per_minute"`

	// Logging and monitoring
	EnableAuditLogging   bool `json:"enable_audit_logging"`
	LogFailedAttempts    bool `json:"log_failed_attempts"`
	EnableSecurityAlerts bool `json:"enable_security_alerts"`
}

// GetDefaultSecurityConfig - Get default security configuration
func GetDefaultSecurityConfig() *SecurityConfig {
	return &SecurityConfig{
		// Authentication settings
		TokenExpiryMinutes: 30,
		MaxLoginAttempts:   5,
		LockoutDuration:    15,

		// Session settings
		SessionTimeoutMinutes: 60,
		MaxConcurrentSessions: 10,

		// Input validation settings
		MaxCommandLength:  1024,
		MaxFilePathLength: 512,
		AllowedFileExtensions: []string{
			".txt", ".log", ".json", ".xml", ".csv", ".md",
			".exe", ".dll", ".so", ".dylib", ".bin",
			".jpg", ".jpeg", ".png", ".gif", ".bmp",
			".pdf", ".doc", ".docx", ".xls", ".xlsx",
		},

		// Network security settings
		AllowedIPRanges:    []string{"0.0.0.0/0"}, // Allow all by default
		RequireHTTPS:       true,
		EnableRateLimiting: true,
		RateLimitRequests:  100,

		// Logging and monitoring
		EnableAuditLogging:   true,
		LogFailedAttempts:    true,
		EnableSecurityAlerts: true,
	}
}

// ValidateSecurityConfig - Validate security configuration
func ValidateSecurityConfig(config *SecurityConfig) error {
	if config.TokenExpiryMinutes < 1 {
		return ErrInvalidConfig
	}
	if config.MaxLoginAttempts < 1 {
		return ErrInvalidConfig
	}
	if config.LockoutDuration < 1 {
		return ErrInvalidConfig
	}
	if config.SessionTimeoutMinutes < 1 {
		return ErrInvalidConfig
	}
	if config.MaxConcurrentSessions < 1 {
		return ErrInvalidConfig
	}
	if config.MaxCommandLength < 1 {
		return ErrInvalidConfig
	}
	if config.MaxFilePathLength < 1 {
		return ErrInvalidConfig
	}
	if config.RateLimitRequests < 1 {
		return ErrInvalidConfig
	}
	return nil
}

// IsIPAllowed - Check if IP is in allowed ranges
func (c *SecurityConfig) IsIPAllowed(ip string) bool {
	// TODO: Implement IP range checking
	// For now, return true if no restrictions are set
	if len(c.AllowedIPRanges) == 0 || (len(c.AllowedIPRanges) == 1 && c.AllowedIPRanges[0] == "0.0.0.0/0") {
		return true
	}
	return true // Placeholder implementation
}

// GetTokenExpiry - Get token expiry duration
func (c *SecurityConfig) GetTokenExpiry() time.Duration {
	return time.Duration(c.TokenExpiryMinutes) * time.Minute
}

// GetSessionTimeout - Get session timeout duration
func (c *SecurityConfig) GetSessionTimeout() time.Duration {
	return time.Duration(c.SessionTimeoutMinutes) * time.Minute
}

// GetLockoutDuration - Get lockout duration
func (c *SecurityConfig) GetLockoutDuration() time.Duration {
	return time.Duration(c.LockoutDuration) * time.Minute
}

// IsFileExtensionAllowed - Check if file extension is allowed
func (c *SecurityConfig) IsFileExtensionAllowed(ext string) bool {
	for _, allowed := range c.AllowedFileExtensions {
		if allowed == ext {
			return true
		}
	}
	return false
}
