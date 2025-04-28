# MCP Terminal Server

A lightweight FastAPI server that can run as a Windows service and exposes an endpoint to execute shell commands and stream their output.

## Features

- Run as a Windows service or in debug mode
- Execute shell commands and stream their output in real-time
- API key authentication
- Rate limiting
- Configurable via environment variables or configuration file
- Robust error handling and logging
- Automatic process restart on failure

## Installation

### Prerequisites

- Windows operating system
- Python 3.7 or higher
- Administrator privileges (for service installation)

### Install Steps

1. Clone this repository or download the source code
2. Open PowerShell as Administrator
3. Navigate to the project directory
4. Run the installation script:

```powershell
.\install_service.ps1
```

This will:
- Install required Python dependencies
- Generate a random API key (or use the one you provide)
- Create a configuration file
- Install and start the Windows service

### Installation Options

You can customize the installation with the following parameters:

```powershell
.\install_service.ps1 -ApiKey "your-api-key" -Port 8080 -Host "127.0.0.1" -LogLevel "debug"
```

Available parameters:
- `-ApiKey`: Custom API key for authentication
- `-Port`: Port number for the server (default: 8000)
- `-Host`: Host address to bind to (default: 0.0.0.0)
- `-LogLevel`: Log level (debug, info, warning, error, critical)
- `-ConfigFile`: Path to a custom configuration file

## Configuration

The server can be configured through:

1. Environment variables
2. Configuration file (config.json)
3. Command-line arguments during installation

### Configuration File

A sample configuration file (`config.json.sample`) is provided. You can copy this to `config.json` and modify it:

```json
{
    "host": "0.0.0.0",
    "port": 8000,
    "log_level": "info",
    "log_file": "mcp_terminal_server.log",
    "max_log_size_mb": 10,
    "log_backup_count": 5,
    "restart_on_failure": true,
    "max_restart_attempts": 5,
    "restart_delay_seconds": 10,
    "shutdown_timeout_seconds": 30,
    "working_directory": null
}
```

### Environment Variables

You can also configure the server using environment variables:

- `MCP_TERMINAL_API_KEY`: API key for authentication
- `MCP_HOST`: Host address to bind to
- `MCP_PORT`: Port number for the server
- `MCP_LOG_LEVEL`: Log level
- `MCP_LOG_FILE`: Path to log file
- `MCP_MAX_LOG_SIZE_MB`: Maximum log file size in MB
- `MCP_LOG_BACKUP_COUNT`: Number of log backup files to keep
- `MCP_RESTART_ON_FAILURE`: Whether to restart the server on failure
- `MCP_MAX_RESTART_ATTEMPTS`: Maximum number of restart attempts
- `MCP_RESTART_DELAY_SECONDS`: Delay between restart attempts
- `MCP_SHUTDOWN_TIMEOUT_SECONDS`: Timeout for graceful shutdown
- `MCP_WORKING_DIRECTORY`: Working directory for the server

## Service Management

### Service Commands

The service can be managed using the following commands:

```powershell
# Install the service
python service.py install

# Start the service
python service.py start

# Stop the service
python service.py stop

# Restart the service
python service.py restart

# Remove the service
python service.py remove

# Update the service configuration
python service.py update

# Run in debug mode (not as a service)
python service.py debug
```

### Logs

Logs are stored in the configured log file (default: `mcp_terminal_server.log`). The logs include:

- Service start/stop events
- Command execution
- Errors and warnings
- Health check results

## API Usage

### Test Client

A robust test client is provided to interact with the server with the following features:

- Command-line arguments for better usability
- API key authentication support
- Colored output for better readability
- Support for saving output to a file
- Robust error handling and logging
- Interactive mode with command history
- Server health check functionality

#### Basic Usage

```powershell
# Run a command
python test_client.py -c "dir" -k "your-api-key"

# Check server health
python test_client.py --health

# Interactive mode
python test_client.py -k "your-api-key"

# Save output to a file
python test_client.py -c "systeminfo" --save-output output.txt

# Specify server URL
python test_client.py -s "http://example.com:8000" -c "dir"

# Enable verbose output
python test_client.py -v -c "dir"

# Show version
python test_client.py --version
```

#### Configuration File

The test client can be configured using a JSON configuration file. Create a `client_config.json` file based on the provided sample:

```json
{
    "server_url": "http://localhost:8000",
    "api_key": "your-api-key-here",
    "timeout": 60,
    "verbose": false
}
```

Then use it with:

```powershell
python test_client.py --config client_config.json
```

#### Environment Variables

The test client also supports configuration via environment variables:

- `MCP_TERMINAL_API_KEY`: API key for authentication
- `MCP_TERMINAL_SERVER_URL`: Server URL

### API Endpoints

- `POST /run`: Execute a command
  - Requires API key in `X-API-Key` header
  - Request body: `{"command": "your command"}`
  - Returns streaming response with command output

- `GET /health`: Check server health
  - Returns `{"status": "healthy", "active_sessions": 0}`

## Security Considerations

- Always change the default API key in production
- Restrict the host to `127.0.0.1` if the server should only be accessible locally
- Consider using HTTPS in production
- The server blocks potentially dangerous commands, but additional security measures may be needed

## Troubleshooting

- Check the log file for errors
- Run in debug mode to see console output: `python service.py debug`
- Verify the service is running: `Get-Service -Name "MCP_Terminal_Server"`
- Check Windows Event Viewer for service-related errors

## License

MIT