package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"

	"go.htdvisser.nl/ssh-gateway/pkg/duo"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func main() {
	// Set up logger
	logConfig := zap.NewDevelopmentConfig()
	logConfig.Level.SetLevel(zapcore.InfoLevel)
	logger, err := logConfig.Build()
	if err != nil {
		log.Fatal("Failed to create logger:", err)
	}

	// Get data directory from command line or use default
	dataDir := "./data"
	if len(os.Args) > 1 {
		dataDir = os.Args[1]
	}

	dataDir, err = filepath.Abs(dataDir)
	if err != nil {
		log.Fatal("Failed to resolve data directory:", err)
	}

	fmt.Printf("Testing Duo integration with data directory: %s\n", dataDir)

	// Test 1: Check if Duo configuration can be loaded
	fmt.Println("\n=== Test 1: Loading Duo Configuration ===")
	config, err := duo.LoadConfig(dataDir)
	if err != nil {
		fmt.Printf("❌ Failed to load Duo config: %v\n", err)
		fmt.Println("   Make sure to copy duo.yaml.example to duo.yaml and configure with real credentials")
	} else {
		fmt.Printf("✅ Duo config loaded successfully\n")
		fmt.Printf("   Integration Key: %s\n", maskString(config.IntegrationKey))
		fmt.Printf("   API Hostname: %s\n", config.APIHostname)
		fmt.Printf("   Push Timeout: %d seconds\n", config.PushTimeout)
	}

	// Test 2: Try to create Duo client
	fmt.Println("\n=== Test 2: Creating Duo Client ===")
	client, err := duo.NewClient(dataDir, logger)
	if err != nil {
		fmt.Printf("❌ Failed to create Duo client: %v\n", err)
		fmt.Println("   This is expected if duo.yaml is not configured with real credentials")
	} else {
		fmt.Printf("✅ Duo client created successfully\n")
		
		// Test API connectivity if client was created
		fmt.Println("\n=== Test 3: Testing API Connectivity ===")
		if err := client.CheckAPIConnectivity(); err != nil {
			fmt.Printf("❌ Duo API connectivity failed: %v\n", err)
		} else {
			fmt.Printf("✅ Duo API connectivity successful\n")
		}
	}

	// Test 3: Check user Duo enablement
	fmt.Println("\n=== Test 4: Checking User Duo Enablement ===")
	testUsers := []string{"alex", "nonexistent", "test"}
	
	for _, username := range testUsers {
		if client != nil {
			enabled := client.IsUserDuoEnabled(username)
			if enabled {
				fmt.Printf("✅ User '%s' has Duo enabled\n", username)
			} else {
				fmt.Printf("⚪ User '%s' does not have Duo enabled\n", username)
			}
		} else {
			// Test without client
			duoFile := filepath.Join(dataDir, "users", fmt.Sprintf("duo_enabled_%s", username))
			if _, err := os.Stat(duoFile); err == nil {
				fmt.Printf("✅ User '%s' has Duo enabled (file exists)\n", username)
			} else {
				fmt.Printf("⚪ User '%s' does not have Duo enabled (no file)\n", username)
			}
		}
	}

	// Test 4: Demo creating a Duo enabled user
	fmt.Println("\n=== Test 5: Creating Duo Enabled User ===")
	if client != nil {
		testUser := "testuser"
		err := client.CreateUserDuoFile(testUser)
		if err != nil {
			fmt.Printf("❌ Failed to create Duo file for user '%s': %v\n", testUser, err)
		} else {
			fmt.Printf("✅ Created Duo enabled file for user '%s'\n", testUser)
			
			// Verify it worked
			if client.IsUserDuoEnabled(testUser) {
				fmt.Printf("✅ Verification: User '%s' is now Duo enabled\n", testUser)
			} else {
				fmt.Printf("❌ Verification failed: User '%s' is not Duo enabled\n", testUser)
			}
		}
	}

	fmt.Println("\n=== Testing Complete ===")
	fmt.Println("\nTo fully test Duo Push authentication:")
	fmt.Println("1. Configure duo.yaml with real Duo credentials")
	fmt.Println("2. Create duo_enabled_<username> files for users who should have Duo")
	fmt.Println("3. Start the SSH gateway and attempt to connect")
	fmt.Println("4. You should receive a push notification on your Duo-enabled device")
}

// maskString masks all but the first and last 4 characters of a string
func maskString(s string) string {
	if len(s) <= 8 {
		return "****"
	}
	return s[:4] + "****" + s[len(s)-4:]
}