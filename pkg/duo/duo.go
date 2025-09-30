// Package duo implements Duo Push authentication for the SSH gateway
package duo

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	duoapi "github.com/duosecurity/duo_api_golang"
	"go.uber.org/zap"
	"gopkg.in/yaml.v2"
)

// Config represents the Duo configuration loaded from duo.yaml
type Config struct {
	IntegrationKey string `yaml:"integration_key"`
	SecretKey      string `yaml:"secret_key"`
	APIHostname    string `yaml:"api_hostname"`
	PushTimeout    int    `yaml:"push_timeout"`
	Device         string `yaml:"device,omitempty"`
}

// Client represents a Duo API client with configuration
type Client struct {
	config    *Config
	duoClient *duoapi.DuoApi
	dataDir   string
	logger    *zap.Logger
}

// NewClient creates a new Duo client
func NewClient(dataDir string, logger *zap.Logger) (*Client, error) {
	config, err := LoadConfig(dataDir)
	if err != nil {
		return nil, err
	}

	// Validate configuration
	if config.IntegrationKey == "" || config.IntegrationKey == "YOUR_INTEGRATION_KEY_HERE" {
		return nil, fmt.Errorf("duo integration_key not configured")
	}
	if config.SecretKey == "" || config.SecretKey == "YOUR_SECRET_KEY_HERE" {
		return nil, fmt.Errorf("duo secret_key not configured")
	}
	if config.APIHostname == "" || config.APIHostname == "YOUR_API_HOSTNAME_HERE" {
		return nil, fmt.Errorf("duo api_hostname not configured")
	}

	// Set default timeout if not specified
	if config.PushTimeout == 0 {
		config.PushTimeout = 60
	}

	// Create Duo API client
	duoClient := duoapi.NewDuoApi(
		config.IntegrationKey,
		config.SecretKey,
		config.APIHostname,
		"ssh-gateway/1.0",
		duoapi.SetTimeout(10*time.Second),
	)

	return &Client{
		config:    config,
		duoClient: duoClient,
		dataDir:   dataDir,
		logger:    logger,
	}, nil
}

// LoadConfig loads Duo configuration from duo.yaml file
func LoadConfig(dataDir string) (*Config, error) {
	configPath := filepath.Join(dataDir, "server", "duo.yaml")
	configBytes, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read duo.yaml: %w", err)
	}

	var config Config
	if err := yaml.Unmarshal(configBytes, &config); err != nil {
		return nil, fmt.Errorf("failed to parse duo.yaml: %w", err)
	}

	return &config, nil
}

// IsUserDuoEnabled checks if Duo is enabled for a specific user by looking for duo_enabled_%username% file
func (c *Client) IsUserDuoEnabled(username string) bool {
	// Clean username to prevent path traversal
	username = strings.ReplaceAll(username, "/", "")
	username = strings.ReplaceAll(username, "\\", "")
	username = strings.ReplaceAll(username, "..", "")

	duoEnabledFile := filepath.Join(c.dataDir, "users", fmt.Sprintf("duo_enabled_%s", username))
	_, err := os.Stat(duoEnabledFile)
	return err == nil
}

// CreateUserDuoFile creates a duo_enabled_%username% file to enable Duo for a user
func (c *Client) CreateUserDuoFile(username string) error {
	username = strings.ReplaceAll(username, "/", "")
	username = strings.ReplaceAll(username, "\\", "")
	username = strings.ReplaceAll(username, "..", "")

	duoEnabledFile := filepath.Join(c.dataDir, "users", fmt.Sprintf("duo_enabled_%s", username))
	
	// Create users directory if it doesn't exist
	usersDir := filepath.Join(c.dataDir, "users")
	if err := os.MkdirAll(usersDir, 0755); err != nil {
		return fmt.Errorf("failed to create users directory: %w", err)
	}

	// Create the duo enabled file with a timestamp
	content := fmt.Sprintf("Duo enabled for user %s on %s\n", username, time.Now().Format(time.RFC3339))
	return os.WriteFile(duoEnabledFile, []byte(content), 0644)
}

// AuthResult represents the result of a Duo authentication request
type AuthResult struct {
	Result string `json:"result"`
	Status string `json:"status"`
	TxId   string `json:"txid,omitempty"`
}

// MessageSender is a function type for sending messages to the SSH client
type MessageSender func(message string) error

// AuthenticateUser performs Duo Push authentication for a user
func (c *Client) AuthenticateUser(ctx context.Context, username, clientIP string) error {
	return c.AuthenticateUserWithMessages(ctx, username, clientIP, nil)
}

// AuthenticateUserWithMessages performs Duo Push authentication with optional message sending
func (c *Client) AuthenticateUserWithMessages(ctx context.Context, username, clientIP string, sendMessage MessageSender) error {
	if !c.IsUserDuoEnabled(username) {
		c.logger.Debug("Duo not enabled for user, skipping authentication", zap.String("username", username))
		return nil
	}

	c.logger.Info("Starting Duo Push authentication", 
		zap.String("username", username),
		zap.String("client_ip", clientIP))

	// First, let's check if the user exists and has devices by doing a preauth
	preAuthResult, err := c.performPreAuth(username)
	if err != nil {
		c.logger.Error("Duo preauth failed", zap.String("username", username), zap.Error(err))
		return fmt.Errorf("duo preauth failed: %w", err)
	}
	
	c.logger.Debug("Duo preauth result", 
		zap.String("username", username),
		zap.Any("preauth", preAuthResult))

	// Prepare authentication request parameters using url.Values
	authParams := make(map[string][]string)
	authParams["username"] = []string{username}
	authParams["factor"] = []string{"push"}
	authParams["ipaddr"] = []string{clientIP}
	authParams["pushinfo"] = []string{fmt.Sprintf("from=ssh%%20gateway&client_ip=%s", url.QueryEscape(clientIP))}
	authParams["device"] = []string{"auto"}
	// Add device if specified in config
	if c.config.Device != "" {
		authParams["device"] = []string{c.config.Device}
	}

	// Convert to url.Values
	params := make(map[string][]string)
	for k, v := range authParams {
		params[k] = v
	}

	// Create a context with timeout for the push request
	pushCtx, cancel := context.WithTimeout(ctx, time.Duration(c.config.PushTimeout)*time.Second)
	defer cancel()

	// Send message to SSH client about push notification
	if sendMessage != nil {
		sendMessage(fmt.Sprintf("Duo Push notification sent to %s. Please check your device and approve the request.\r\n", username))
	}

	c.logger.Info("Sending Duo Push notification", zap.String("username", username))

	// Start the authentication in a goroutine
	type authResult struct {
		result *AuthResult
		err    error
	}
	resultChan := make(chan authResult, 1)

	go func() {
		result, err := c.performAuth(params)
		resultChan <- authResult{result: result, err: err}
	}()

	// Wait for either the authentication to complete or context timeout
	select {
	case <-pushCtx.Done():
		if sendMessage != nil {
			sendMessage(fmt.Sprintf("Duo Push authentication timed out after %d seconds. Please try again.\r\n", c.config.PushTimeout))
		}
		c.logger.Warn("Duo Push authentication timed out", 
			zap.String("username", username),
			zap.Duration("timeout", time.Duration(c.config.PushTimeout)*time.Second))
		return fmt.Errorf("duo push authentication timed out after %d seconds", c.config.PushTimeout)

	case authRes := <-resultChan:
		if authRes.err != nil {
			if sendMessage != nil {
				sendMessage(fmt.Sprintf("Duo authentication failed: %v\r\n", authRes.err))
			}
			c.logger.Error("Duo API call failed", 
				zap.String("username", username),
				zap.Error(authRes.err))
			return fmt.Errorf("duo authentication failed: %w", authRes.err)
		}

		result := authRes.result
		c.logger.Info("Duo authentication result", 
			zap.String("username", username),
			zap.String("result", result.Result),
			zap.String("status", result.Status))

		switch result.Result {
		case "allow":
			if sendMessage != nil {
				sendMessage("Duo Push authentication approved. Connecting to server...\r\n")
			}
			c.logger.Info("Duo Push authentication successful", zap.String("username", username))
			return nil
		case "deny":
			if sendMessage != nil {
				sendMessage("Duo Push authentication denied. Access rejected.\r\n")
			}
			c.logger.Warn("Duo Push authentication denied", zap.String("username", username))
			return fmt.Errorf("duo authentication denied")
		default:
			if sendMessage != nil {
				sendMessage(fmt.Sprintf("Duo Push authentication failed: %s\r\n", result.Status))
			}
			c.logger.Warn("Duo Push authentication failed", 
				zap.String("username", username),
				zap.String("result", result.Result),
				zap.String("status", result.Status))
			return fmt.Errorf("duo authentication failed: %s", result.Status)
		}
	}
}

// performAuth makes the actual Duo API call for authentication
func (c *Client) performAuth(params map[string][]string) (*AuthResult, error) {
	// Convert map to url.Values
	urlParams := url.Values(params)
	
	// Debug logging to see what parameters are being sent
	c.logger.Debug("Duo API request parameters", zap.Any("params", params))
	
	// Make the API call to Duo's auth endpoint
	resp, body, err := c.duoClient.SignedCall("POST", "/auth/v2/auth", urlParams)
	if err != nil {
		return nil, fmt.Errorf("duo API call failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		// Try to parse error response for better error messages
		var errorResponse struct {
			Code          int    `json:"code"`
			Message       string `json:"message"`
			MessageDetail string `json:"message_detail"`
			Stat          string `json:"stat"`
		}
		
		if json.Unmarshal(body, &errorResponse) == nil && errorResponse.Stat == "FAIL" {
			return nil, fmt.Errorf("duo API error (code %d): %s - %s", 
				errorResponse.Code, errorResponse.Message, errorResponse.MessageDetail)
		}
		
		return nil, fmt.Errorf("duo API returned status %d: %s", resp.StatusCode, string(body))
	}

	// Parse the JSON response
	var duoResponse struct {
		Response AuthResult `json:"response"`
		Stat     string     `json:"stat"`
	}

	if err := json.Unmarshal(body, &duoResponse); err != nil {
		return nil, fmt.Errorf("failed to parse duo response: %w", err)
	}

	if duoResponse.Stat != "OK" {
		return nil, fmt.Errorf("duo API returned error status: %s", duoResponse.Stat)
	}

	return &duoResponse.Response, nil
}

// performPreAuth checks what authentication options are available for a user
func (c *Client) performPreAuth(username string) (map[string]interface{}, error) {
	params := url.Values{}
	params.Set("username", username)
	
	resp, body, err := c.duoClient.SignedCall("POST", "/auth/v2/preauth", params)
	if err != nil {
		return nil, fmt.Errorf("duo preauth API call failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		// Try to parse error response for better error messages
		var errorResponse struct {
			Code          int    `json:"code"`
			Message       string `json:"message"`
			MessageDetail string `json:"message_detail"`
			Stat          string `json:"stat"`
		}
		
		if json.Unmarshal(body, &errorResponse) == nil && errorResponse.Stat == "FAIL" {
			return nil, fmt.Errorf("duo preauth API error (code %d): %s - %s", 
				errorResponse.Code, errorResponse.Message, errorResponse.MessageDetail)
		}
		
		return nil, fmt.Errorf("duo preauth API returned status %d: %s", resp.StatusCode, string(body))
	}

	// Parse the JSON response
	var duoResponse struct {
		Response map[string]interface{} `json:"response"`
		Stat     string                 `json:"stat"`
	}

	if err := json.Unmarshal(body, &duoResponse); err != nil {
		return nil, fmt.Errorf("failed to parse duo preauth response: %w", err)
	}

	if duoResponse.Stat != "OK" {
		return nil, fmt.Errorf("duo preauth API returned error status: %s", duoResponse.Stat)
	}

	return duoResponse.Response, nil
}

// CheckAPIConnectivity tests if we can connect to the Duo API
func (c *Client) CheckAPIConnectivity() error {
	c.logger.Debug("Checking Duo API connectivity")
	
	// Use the ping endpoint to test connectivity
	resp, body, err := c.duoClient.SignedCall("GET", "/auth/v2/ping", url.Values{})
	if err != nil {
		return fmt.Errorf("duo API connectivity check failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return fmt.Errorf("duo API ping failed with status %d: %s", resp.StatusCode, string(body))
	}

	c.logger.Debug("Duo API connectivity check successful")
	return nil
}
