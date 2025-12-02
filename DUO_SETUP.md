# Duo Push Authentication Integration

This SSH Gateway now supports Duo Push authentication for enhanced security. Users can be configured to require Duo Push approval before being granted access to upstream servers.

## How It Works

1. **SSH Key Authentication**: User connects with their SSH key (existing functionality)
2. **Duo Push Authentication**: If Duo is enabled for the user, a push notification is sent to their registered device
3. **User Approval**: User approves/denies the request on their device
4. **Connection Forwarding**: Only after both SSH key AND Duo Push approval, the connection is forwarded to the upstream server

## Setup Instructions

### 1. Configure Duo Application

1. Log into your Duo Admin Panel
2. Go to **Applications** → **Protect an Application** → **Auth API**
3. Note down the following values:
   - Integration Key
   - Secret Key
   - API Hostname

### 2. Configure SSH Gateway

1. Copy the example configuration:

   ```bash
   cp data/server/duo.yaml.example data/server/duo.yaml
   ```

2. Edit `data/server/duo.yaml` with your Duo credentials:

   ```yaml
   # Duo Security Configuration
   integration_key: "YOUR_ACTUAL_INTEGRATION_KEY"
   secret_key: "YOUR_ACTUAL_SECRET_KEY"
   api_hostname: "api-xxxxxxxx.duosecurity.com"

   # Optional settings
   push_timeout: 60 # seconds to wait for push response
   # device: "phone1"  # force specific device
   ```

### 3. Enable Duo for Specific Users

Create a file `data/users/duo_enabled_<username>` for each user who should have Duo authentication:

```bash
# Enable Duo for user 'alice'
echo "Duo enabled for alice on $(date)" > data/users/duo_enabled_alice

# Enable Duo for user 'bob'
echo "Duo enabled for bob on $(date)" > data/users/duo_enabled_bob
```

**Important**: The filename must match the pattern `duo_enabled_<username>` where `<username>` is the SSH username.

### 4. Start SSH Gateway

Start the gateway as usual:

```bash
./ssh-gateway --data ./data
```

You should see log messages indicating Duo configuration was loaded:

```
INFO  Loaded Duo configuration successfully
INFO  Duo API connectivity verified
```

## User Experience

### For Users WITHOUT Duo Enabled

- Authentication works exactly as before (SSH key only)
- No push notifications are sent
- Connection proceeds immediately after SSH key validation

### For Users WITH Duo Enabled

- SSH key authentication happens first
- A push notification is sent to their registered Duo device
- User must approve the request within the timeout period (default: 60 seconds)
- Only after approval is the connection forwarded to upstream

Example user experience:

```bash
$ ssh test@gateway.example.com
# SSH key authentication succeeds
# Push notification sent: "SSH login to gateway from 192.168.1.100"
# User receives push on phone/device and approves
# Connection proceeds to upstream server
```

## Configuration Files

### Duo Configuration (`data/server/duo.yaml`)

```yaml
integration_key: "DI..." # From Duo Admin Panel
secret_key: "secret123..." # From Duo Admin Panel
api_hostname: "api-xxx.duosecurity.com" # From Duo Admin Panel
push_timeout: 60 # Timeout in seconds (optional)
device: "phone1" # Force specific device (optional)
```

### User Duo Enablement (`data/users/duo_enabled_<username>`)

- File presence enables Duo for that user
- File contents are ignored (can be empty or contain notes)
- Filename must match exact pattern: `duo_enabled_<username>`

## Testing & Verification

Run the included test utility:

```bash
go run test/duo_demo.go
```

This will verify:

- ✅ Duo configuration loads correctly
- ✅ API connectivity (if real credentials provided)
- ✅ User Duo enablement detection
- ✅ Duo file creation functionality

## Security Considerations

1. **Defense in Depth**: Duo Push adds a second factor after SSH key authentication
2. **Per-User Control**: Duo can be enabled/disabled per user by file presence
3. **Timeout Protection**: Push requests timeout to prevent indefinite waiting
4. **Logging**: All Duo authentication attempts are logged for audit

## Troubleshooting

### "Duo not configured" message

- Check that `data/server/duo.yaml` exists and has valid credentials
- Verify credentials in Duo Admin Panel

### "Duo API connectivity check failed"

- Check API hostname is correct (include full domain)
- Verify integration key and secret key are correct
- Check network connectivity to Duo's servers

### "Duo authentication timed out"

- User didn't respond to push within timeout period
- Check user has Duo app installed and properly enrolled
- Verify push_timeout setting (default 60 seconds)

### "Duo authentication denied"

- User explicitly denied the push request
- Check with user if they intended to deny access

## Log Messages

Key log messages to watch for:

```
INFO  Loaded Duo configuration successfully        # Duo config loaded
INFO  Duo API connectivity verified               # API connection works
INFO  Starting Duo Push authentication user=alice # Push sent
INFO  Duo Push authentication completed successfully # User approved
WARN  Duo Push authentication failed              # User denied or timeout
```

## Advanced Usage

### Programmatic User Management

Enable Duo for a user programmatically:

```go
import "go.htdvisser.nl/ssh-gateway/pkg/duo"

client, _ := duo.NewClient("/path/to/data", logger)
err := client.CreateUserDuoFile("username")
```

Check if user has Duo enabled:

```go
enabled := client.IsUserDuoEnabled("username")
```

### Custom Push Messages

The push notification includes:

- Action: "SSH login to gateway from <IP>"
- IP address of connecting client
- Timestamp of request

This helps users identify legitimate vs. unauthorized access attempts.

## Migration from Non-Duo Setup

1. Deploy Duo configuration files
2. Restart SSH gateway
3. Gradually enable users by creating `duo_enabled_<username>` files
4. Monitor logs to ensure smooth operation
5. Users without Duo files will continue working normally

No existing functionality is affected - Duo is purely additive security.
