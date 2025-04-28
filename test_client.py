#!/usr/bin/env python3
"""
MCP Terminal Server - Test Client

This script provides a robust client to interact with the MCP Terminal Server by sending
commands and displaying the streamed output with enhanced features:

Features:
- Command-line arguments for better usability
- API key authentication support
- Colored output for better readability
- Support for saving output to a file
- Robust error handling and logging
- Interactive mode with command history
- Server health check functionality

Usage:
    python test_client.py -c "dir" -s http://localhost:8000 -k your-api-key
    python test_client.py --health
    python test_client.py --save-output output.txt -c "systeminfo"
    python test_client.py  # Interactive mode

Author: MCP Terminal Server Team
License: MIT
"""

import argparse
import json
import logging
import os
import platform
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, Optional, TextIO, Union

import requests
from requests.exceptions import ConnectionError, RequestException, Timeout

# Set up version
__version__ = "1.1.0"

# Default values
DEFAULT_SERVER_URL = "http://localhost:8000"
DEFAULT_API_KEY = "dev-api-key-change-me-in-production"
DEFAULT_TIMEOUT = 30  # seconds
DEFAULT_CONFIG_FILE = "client_config.json"

# ANSI color codes
COLORS = {
    "reset": "\033[0m",
    "red": "\033[91m",
    "green": "\033[92m",
    "yellow": "\033[93m",
    "blue": "\033[94m",
    "magenta": "\033[95m",
    "cyan": "\033[96m",
    "white": "\033[97m",
    "bold": "\033[1m",
}

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler()],
)
logger = logging.getLogger("mcp-terminal-client")


def supports_color() -> bool:
    """
    Check if the terminal supports color output.
    
    Returns:
        bool: True if color is supported, False otherwise
    """
    # Windows 10 and higher supports ANSI colors in cmd.exe
    if platform.system() == "Windows":
        if int(platform.release()) >= 10:
            return True
        return False
    
    # Check if output is a TTY
    if not sys.stdout.isatty():
        return False
    
    # Check for NO_COLOR environment variable
    if os.environ.get("NO_COLOR"):
        return False
    
    # Check for TERM environment variable
    term = os.environ.get("TERM", "")
    if term == "dumb":
        return False
    
    return True


def colorize(text: str, color: str) -> str:
    """
    Add color to text if supported by the terminal.
    
    Args:
        text: The text to colorize
        color: The color to use (must be a key in the COLORS dict)
        
    Returns:
        The colorized text if supported, otherwise the original text
    """
    if not supports_color() or color not in COLORS:
        return text
    
    return f"{COLORS[color]}{text}{COLORS['reset']}"


def load_config(config_file: str) -> Dict:
    """
    Load configuration from a JSON file.
    
    Args:
        config_file: Path to the configuration file
        
    Returns:
        Dict containing configuration values
    """
    config = {}
    config_path = Path(config_file)
    
    if config_path.exists():
        try:
            with open(config_path, "r") as f:
                config = json.load(f)
            logger.debug(f"Loaded configuration from {config_file}")
        except json.JSONDecodeError:
            logger.warning(f"Failed to parse configuration file: {config_file}")
        except Exception as e:
            logger.warning(f"Error loading configuration: {str(e)}")
    
    return config


def save_output_to_file(output: str, file_path: str) -> None:
    """
    Save command output to a file.
    
    Args:
        output: The command output to save
        file_path: Path to the output file
    """
    try:
        with open(file_path, "w") as f:
            f.write(output)
        logger.info(f"Output saved to {file_path}")
    except Exception as e:
        logger.error(f"Failed to save output to {file_path}: {str(e)}")


def send_command(
    command: str, 
    server_url: str = DEFAULT_SERVER_URL, 
    api_key: Optional[str] = None,
    timeout: int = DEFAULT_TIMEOUT,
    output_file: Optional[str] = None,
    verbose: bool = False
) -> bool:
    """
    Send a command to the MCP Terminal Server and stream the output.
    
    Args:
        command: The command to execute
        server_url: The base URL of the server
        api_key: The API key for authentication
        timeout: Request timeout in seconds
        output_file: Path to save the output (optional)
        verbose: Whether to show verbose output
        
    Returns:
        bool: True if the command was executed successfully, False otherwise
    """
    url = f"{server_url}/run"
    headers = {
        "Content-Type": "application/json",
    }
    
    # Add API key if provided
    if api_key:
        headers["X-API-Key"] = api_key
    
    payload = {"command": command}
    full_output = []  # Store complete output for file saving

    try:
        if verbose:
            logger.info(f"Sending command: {command}")
            logger.info(f"Server URL: {url}")
            logger.info("Waiting for response...")
        else:
            print(colorize(f"Sending command: {command}", "cyan"))
            print(f"Server URL: {url}")
            print("Waiting for response...\n")
        
        # Start timer for performance measurement
        start_time = time.time()
        
        response = requests.post(
            url, 
            json=payload, 
            stream=True, 
            headers=headers,
            timeout=timeout
        )
        
        # Get session ID from headers if available
        session_id = response.headers.get("X-Session-ID", "Unknown")
        
        if response.status_code == 200:
            if verbose:
                logger.info(f"Session ID: {session_id}")
                logger.info("Streaming output...")
            else:
                print(colorize(f"Session ID: {session_id}", "green"))
                print(colorize("Streaming output:", "green") + "\n" + "-" * 50)
            
            for chunk in response.iter_lines():
                if chunk:
                    line = chunk.decode()
                    full_output.append(line)
                    
                    # Format the output based on the source
                    if line.startswith("[STDERR]"):
                        # Red text for stderr
                        formatted_line = colorize(line, "red")
                    elif line.startswith("[SYSTEM]"):
                        # Blue text for system messages
                        formatted_line = colorize(line, "blue")
                    else:
                        formatted_line = line
                    
                    print(formatted_line)
            
            # Calculate and display execution time
            execution_time = time.time() - start_time
            completion_message = f"\n{'-' * 50}\nCommand execution completed in {execution_time:.2f} seconds."
            print(colorize(completion_message, "green"))
            full_output.append(completion_message)
            
            # Save output to file if requested
            if output_file:
                save_output_to_file("\n".join(full_output), output_file)
            
            return True
            
        else:
            error_message = f"Error: {response.status_code} - {response.text}"
            logger.error(error_message)
            print(colorize(error_message, "red"))
            return False
            
    except ConnectionError:
        error_message = f"Connection error: Could not connect to {server_url}"
        logger.error(error_message)
        print(colorize(error_message, "red"))
        return False
    except Timeout:
        error_message = f"Timeout error: The request timed out after {timeout} seconds"
        logger.error(error_message)
        print(colorize(error_message, "red"))
        return False
    except RequestException as e:
        error_message = f"Request failed: {str(e)}"
        logger.error(error_message)
        print(colorize(error_message, "red"))
        return False
    except KeyboardInterrupt:
        print(colorize("\nRequest interrupted by user.", "yellow"))
        return False
    except Exception as e:
        error_message = f"Unexpected error: {str(e)}"
        logger.error(error_message)
        print(colorize(error_message, "red"))
        return False


def check_server_health(
    server_url: str = DEFAULT_SERVER_URL,
    timeout: int = DEFAULT_TIMEOUT,
    verbose: bool = False
) -> bool:
    """
    Check if the server is running and healthy.
    
    Args:
        server_url: The base URL of the server
        timeout: Request timeout in seconds
        verbose: Whether to show verbose output
        
    Returns:
        bool: True if the server is healthy, False otherwise
    """
    try:
        if verbose:
            logger.info(f"Checking server health at {server_url}/health")
        
        response = requests.get(f"{server_url}/health", timeout=timeout)
        
        if response.status_code == 200:
            health_data = response.json()
            active_sessions = health_data.get('active_sessions', 'Unknown')
            
            health_message = f"Server is healthy. Active sessions: {active_sessions}"
            if verbose:
                logger.info(health_message)
            else:
                print(colorize(health_message, "green"))
                
            # Print additional health data if available
            for key, value in health_data.items():
                if key != 'active_sessions' and key != 'status':
                    print(f"  {key}: {value}")
                    
            return True
        else:
            error_message = f"Server returned status code: {response.status_code}"
            logger.error(error_message)
            print(colorize(error_message, "red"))
            return False
            
    except ConnectionError:
        error_message = f"Connection error: Could not connect to {server_url}"
        logger.error(error_message)
        print(colorize(error_message, "red"))
        return False
    except Timeout:
        error_message = f"Timeout error: The request timed out after {timeout} seconds"
        logger.error(error_message)
        print(colorize(error_message, "red"))
        return False
    except Exception as e:
        error_message = f"Failed to connect to server: {str(e)}"
        logger.error(error_message)
        print(colorize(error_message, "red"))
        return False


def interactive_mode(
    server_url: str, 
    api_key: str, 
    timeout: int,
    output_file: Optional[str],
    verbose: bool
) -> None:
    """
    Run the client in interactive mode, allowing the user to enter commands.
    
    Args:
        server_url: The base URL of the server
        api_key: The API key for authentication
        timeout: Request timeout in seconds
        output_file: Path to save the output (optional)
        verbose: Whether to show verbose output
    """
    print(colorize("MCP Terminal Server - Test Client", "cyan"))
    print(colorize(f"Version: {__version__}", "cyan"))
    print(colorize(f"Server: {server_url}", "cyan"))
    print(colorize("Type 'exit' or 'quit' to exit", "yellow"))
    print(colorize("Type 'health' to check server health", "yellow"))
    print(colorize("Type 'help' to show available commands", "yellow"))
    
    # Check server health on startup
    check_server_health(server_url, timeout, verbose)
    
    while True:
        try:
            cmd = input(colorize("\nEnter a command: ", "green"))
            
            if cmd.lower() in ("exit", "quit"):
                print(colorize("Exiting...", "yellow"))
                break
            elif cmd.lower() == "health":
                check_server_health(server_url, timeout, verbose)
            elif cmd.lower() == "help":
                print(colorize("Available commands:", "cyan"))
                print("  exit, quit - Exit the client")
                print("  health - Check server health")
                print("  help - Show this help message")
                print("  version - Show client version")
                print("  clear - Clear the screen")
                print("  Any other input will be sent as a command to the server")
            elif cmd.lower() == "version":
                print(colorize(f"MCP Terminal Client v{__version__}", "cyan"))
            elif cmd.lower() == "clear":
                os.system('cls' if platform.system() == 'Windows' else 'clear')
            elif cmd.strip():
                # Generate a timestamped output file if requested
                current_output_file = None
                if output_file:
                    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                    file_name = f"{Path(output_file).stem}_{timestamp}{Path(output_file).suffix}"
                    current_output_file = str(Path(output_file).parent / file_name)
                
                send_command(cmd, server_url, api_key, timeout, current_output_file, verbose)
        except KeyboardInterrupt:
            print(colorize("\nExiting...", "yellow"))
            break
        except EOFError:
            print(colorize("\nExiting...", "yellow"))
            break


def main():
    """Main function to parse arguments and execute commands."""
    parser = argparse.ArgumentParser(
        description="Test client for MCP Terminal Server",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    
    # Command execution options
    parser.add_argument("--command", "-c", help="Command to execute")
    parser.add_argument("--server", "-s", default=DEFAULT_SERVER_URL, help="Server URL")
    parser.add_argument("--api-key", "-k", help="API key for authentication")
    parser.add_argument("--timeout", "-t", type=int, default=DEFAULT_TIMEOUT, 
                        help="Request timeout in seconds")
    
    # Output options
    parser.add_argument("--save-output", "-o", help="Save output to file")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose output")
    
    # Server health check
    parser.add_argument("--health", action="store_true", help="Check server health")
    
    # Configuration options
    parser.add_argument("--config", help=f"Path to configuration file (default: {DEFAULT_CONFIG_FILE})")
    
    # Version information
    parser.add_argument("--version", action="version", 
                        version=f"MCP Terminal Client v{__version__}")
    
    args = parser.parse_args()
    
    # Set log level based on verbose flag
    if args.verbose:
        logger.setLevel(logging.DEBUG)
    
    # Load configuration from file if specified
    config = {}
    if args.config:
        config = load_config(args.config)
    elif os.path.exists(DEFAULT_CONFIG_FILE):
        config = load_config(DEFAULT_CONFIG_FILE)
    
    # Use API key from arguments, environment variable, config file, or default
    api_key = (args.api_key or 
               os.environ.get("MCP_TERMINAL_API_KEY") or 
               config.get("api_key") or 
               DEFAULT_API_KEY)
    
    # Use server URL from arguments, environment variable, config file, or default
    server_url = (args.server or 
                  os.environ.get("MCP_TERMINAL_SERVER_URL") or 
                  config.get("server_url") or 
                  DEFAULT_SERVER_URL)
    
    # Use timeout from arguments, config file, or default
    timeout = args.timeout or config.get("timeout", DEFAULT_TIMEOUT)
    
    if args.health:
        check_server_health(server_url, timeout, args.verbose)
        return
    
    if args.command:
        send_command(args.command, server_url, api_key, timeout, args.save_output, args.verbose)
    else:
        # Interactive mode
        interactive_mode(server_url, api_key, timeout, args.save_output, args.verbose)


if __name__ == "__main__":
    main()
