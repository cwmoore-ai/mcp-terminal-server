"""
MCP Terminal Server - Windows Service Wrapper

This module provides a Windows service wrapper for the MCP Terminal Server FastAPI application.
It handles service installation, removal, starting, stopping, and runtime management.

The service can be configured through:
1. Environment variables
2. Configuration file (config.json)
3. Command-line arguments

Usage:
    python service.py install   # Install the service
    python service.py start     # Start the service
    python service.py stop      # Stop the service
    python service.py remove    # Remove the service
    python service.py update    # Update the service configuration
    python service.py debug     # Run in debug mode (not as a service)

Author: MCP Terminal Server Team
License: MIT
"""

import json
import logging
import logging.handlers
import os
import pathlib
import signal
import subprocess
import sys
import time
from typing import Dict, List, Optional, Union, Any

import win32event
import win32service
import win32serviceutil
import servicemanager

# Configure logging
LOG_LEVELS = {
    "debug": logging.DEBUG,
    "info": logging.INFO,
    "warning": logging.WARNING,
    "error": logging.ERROR,
    "critical": logging.CRITICAL
}

# Default configuration
DEFAULT_CONFIG = {
    "host": "0.0.0.0",
    "port": 8000,
    "log_level": "info",
    "log_file": "mcp_terminal_server.log",
    "max_log_size_mb": 10,
    "log_backup_count": 5,
    "restart_on_failure": True,
    "max_restart_attempts": 5,
    "restart_delay_seconds": 10,
    "shutdown_timeout_seconds": 30,
    "working_directory": None  # Will be set to script directory if None
}


class ConfigManager:
    """
    Manages configuration for the MCP Terminal Server service.
    
    Loads configuration from:
    1. Default values
    2. Configuration file (if exists)
    3. Environment variables (overrides file settings)
    """
    
    def __init__(self, config_file: str = "config.json"):
        """
        Initialize the configuration manager.
        
        Args:
            config_file: Path to the configuration file (relative to working directory)
        """
        self.config_file = config_file
        self.config = DEFAULT_CONFIG.copy()
        
        # Set working directory to script directory by default
        if not self.config["working_directory"]:
            self.config["working_directory"] = os.path.dirname(os.path.abspath(__file__))
        
        # Load configuration from file if it exists
        self._load_from_file()
        
        # Override with environment variables
        self._load_from_env()
    
    def _load_from_file(self) -> None:
        """Load configuration from the config file if it exists."""
        try:
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r') as f:
                    file_config = json.load(f)
                    self.config.update(file_config)
        except Exception as e:
            # Just log the error, don't fail (use defaults)
            print(f"Warning: Failed to load config file: {e}")
    
    def _load_from_env(self) -> None:
        """Load configuration from environment variables."""
        env_mapping = {
            "MCP_HOST": "host",
            "MCP_PORT": ("port", int),
            "MCP_LOG_LEVEL": "log_level",
            "MCP_LOG_FILE": "log_file",
            "MCP_MAX_LOG_SIZE_MB": ("max_log_size_mb", int),
            "MCP_LOG_BACKUP_COUNT": ("log_backup_count", int),
            "MCP_RESTART_ON_FAILURE": ("restart_on_failure", lambda x: x.lower() == "true"),
            "MCP_MAX_RESTART_ATTEMPTS": ("max_restart_attempts", int),
            "MCP_RESTART_DELAY_SECONDS": ("restart_delay_seconds", int),
            "MCP_SHUTDOWN_TIMEOUT_SECONDS": ("shutdown_timeout_seconds", int),
            "MCP_WORKING_DIRECTORY": "working_directory"
        }
        
        for env_var, config_key in env_mapping.items():
            # Check if the environment variable exists
            if env_var in os.environ:
                # Handle conversion if needed
                if isinstance(config_key, tuple):
                    key_name, converter = config_key
                    try:
                        self.config[key_name] = converter(os.environ[env_var])
                    except (ValueError, TypeError):
                        print(f"Warning: Failed to convert environment variable {env_var}")
                else:
                    self.config[key_name] = os.environ[env_var]
    
    def get(self, key: str, default: Any = None) -> Any:
        """
        Get a configuration value.
        
        Args:
            key: The configuration key
            default: Default value if key doesn't exist
            
        Returns:
            The configuration value or default
        """
        return self.config.get(key, default)
    
    def save(self) -> None:
        """Save the current configuration to the config file."""
        try:
            with open(self.config_file, 'w') as f:
                json.dump(self.config, f, indent=4)
        except Exception as e:
            print(f"Error saving configuration: {e}")


class ServiceLogger:
    """
    Handles logging for the MCP Terminal Server service.
    
    Features:
    - Log rotation
    - Multiple log levels
    - Console and file output
    """
    
    def __init__(self, config: ConfigManager):
        """
        Initialize the logger.
        
        Args:
            config: Configuration manager instance
        """
        self.config = config
        self.logger = logging.getLogger("mcp_terminal_server")
        
        # Set log level
        log_level_name = config.get("log_level", "info").lower()
        log_level = LOG_LEVELS.get(log_level_name, logging.INFO)
        self.logger.setLevel(log_level)
        
        # Clear existing handlers
        self.logger.handlers = []
        
        # Create formatter
        formatter = logging.Formatter(
            "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
        )
        
        # Add file handler with rotation
        log_file = config.get("log_file")
        if log_file:
            # Ensure log file path is absolute
            if not os.path.isabs(log_file):
                log_file = os.path.join(config.get("working_directory"), log_file)
                
            # Ensure log directory exists
            log_dir = os.path.dirname(log_file)
            if log_dir and not os.path.exists(log_dir):
                os.makedirs(log_dir, exist_ok=True)
                
            # Create rotating file handler
            max_bytes = config.get("max_log_size_mb", 10) * 1024 * 1024
            backup_count = config.get("log_backup_count", 5)
            
            file_handler = logging.handlers.RotatingFileHandler(
                log_file,
                maxBytes=max_bytes,
                backupCount=backup_count
            )
            file_handler.setFormatter(formatter)
            self.logger.addHandler(file_handler)
        
        # Add console handler for debug mode
        if "debug" in sys.argv:
            console_handler = logging.StreamHandler()
            console_handler.setFormatter(formatter)
            self.logger.addHandler(console_handler)
    
    def debug(self, message: str) -> None:
        """Log a debug message."""
        self.logger.debug(message)
    
    def info(self, message: str) -> None:
        """Log an info message."""
        self.logger.info(message)
    
    def warning(self, message: str) -> None:
        """Log a warning message."""
        self.logger.warning(message)
    
    def error(self, message: str) -> None:
        """Log an error message."""
        self.logger.error(message)
    
    def critical(self, message: str) -> None:
        """Log a critical message."""
        self.logger.critical(message)


class ProcessManager:
    """
    Manages the FastAPI server process.
    
    Features:
    - Process startup and shutdown
    - Restart on failure
    - Health monitoring
    """
    
    def __init__(self, config: ConfigManager, logger: ServiceLogger):
        """
        Initialize the process manager.
        
        Args:
            config: Configuration manager instance
            logger: Service logger instance
        """
        self.config = config
        self.logger = logger
        self.process = None
        self.restart_count = 0
        self.running = False
    
    def start(self) -> bool:
        """
        Start the FastAPI server process.
        
        Returns:
            True if started successfully, False otherwise
        """
        if self.process and self.process.poll() is None:
            self.logger.warning("Process already running")
            return True
        
        try:
            # Set working directory
            working_dir = self.config.get("working_directory")
            if working_dir and os.path.exists(working_dir):
                os.chdir(working_dir)
                self.logger.info(f"Changed working directory to: {working_dir}")
            
            # Build command
            python_exe = sys.executable
            host = self.config.get("host")
            port = self.config.get("port")
            
            uvicorn_cmd = [
                python_exe, "-m", "uvicorn", "main:app",
                "--host", str(host), "--port", str(port)
            ]
            
            # Start the process
            self.logger.info(f"Starting FastAPI server: {' '.join(uvicorn_cmd)}")
            self.process = subprocess.Popen(
                uvicorn_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=working_dir
            )
            
            # Check if process started successfully
            if self.process.poll() is None:
                self.logger.info(f"FastAPI server started with PID: {self.process.pid}")
                self.running = True
                self.restart_count = 0
                return True
            else:
                self.logger.error(f"Failed to start FastAPI server, exit code: {self.process.returncode}")
                return False
                
        except Exception as e:
            self.logger.error(f"Error starting FastAPI server: {str(e)}")
            return False
    
    def stop(self) -> bool:
        """
        Stop the FastAPI server process gracefully.
        
        Returns:
            True if stopped successfully, False otherwise
        """
        if not self.process:
            self.logger.warning("No process to stop")
            self.running = False
            return True
        
        try:
            # Try graceful shutdown first
            self.logger.info("Attempting graceful shutdown...")
            
            # Send SIGTERM (graceful shutdown)
            self.process.terminate()
            
            # Wait for process to terminate
            shutdown_timeout = self.config.get("shutdown_timeout_seconds", 30)
            for _ in range(shutdown_timeout):
                if self.process.poll() is not None:
                    self.logger.info(f"Process terminated gracefully with exit code: {self.process.returncode}")
                    self.running = False
                    return True
                time.sleep(1)
            
            # Force kill if still running
            self.logger.warning(f"Process did not terminate after {shutdown_timeout} seconds, forcing kill")
            self.process.kill()
            
            # Wait for process to be killed
            self.process.wait(timeout=5)
            self.logger.info(f"Process killed with exit code: {self.process.returncode}")
            self.running = False
            return True
            
        except Exception as e:
            self.logger.error(f"Error stopping process: {str(e)}")
            self.running = False
            return False
    
    def restart(self) -> bool:
        """
        Restart the FastAPI server process.
        
        Returns:
            True if restarted successfully, False otherwise
        """
        self.logger.info("Restarting FastAPI server...")
        self.stop()
        return self.start()
    
    def check_health(self) -> bool:
        """
        Check if the process is healthy.
        
        Returns:
            True if healthy, False otherwise
        """
        if not self.process:
            return False
        
        # Check if process is still running
        if self.process.poll() is not None:
            self.logger.warning(f"Process exited with code: {self.process.returncode}")
            
            # Handle restart on failure
            if self.config.get("restart_on_failure", True):
                max_attempts = self.config.get("max_restart_attempts", 5)
                
                if self.restart_count < max_attempts:
                    self.restart_count += 1
                    delay = self.config.get("restart_delay_seconds", 10)
                    
                    self.logger.info(f"Restarting in {delay} seconds (attempt {self.restart_count}/{max_attempts})...")
                    time.sleep(delay)
                    
                    return self.start()
                else:
                    self.logger.error(f"Exceeded maximum restart attempts ({max_attempts})")
                    return False
            else:
                return False
        
        return True


class MCPServerService(win32serviceutil.ServiceFramework):
    """
    Windows service implementation for the MCP Terminal Server.
    
    This class handles the Windows service lifecycle events and manages
    the FastAPI server process.
    """
    
    _svc_name_ = "MCP_Terminal_Server"
    _svc_display_name_ = "MCP Terminal Server"
    _svc_description_ = "Runs a lightweight MCP server for live terminal commands."
    
    def __init__(self, args):
        """
        Initialize the service.
        
        Args:
            args: Service arguments
        """
        win32serviceutil.ServiceFramework.__init__(self, args)
        self.hWaitStop = win32event.CreateEvent(None, 0, 0, None)
        self.config = ConfigManager()
        self.logger = ServiceLogger(self.config)
        self.process_manager = ProcessManager(self.config, self.logger)
        
        # Set up signal handlers
        signal.signal(signal.SIGTERM, self._handle_signal)
        signal.signal(signal.SIGINT, self._handle_signal)
    
    def _handle_signal(self, signum, frame):
        """
        Handle termination signals.
        
        Args:
            signum: Signal number
            frame: Current stack frame
        """
        self.logger.info(f"Received signal {signum}, stopping service")
        self.SvcStop()
    
    def SvcStop(self):
        """Handle service stop request."""
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        self.logger.info("Service stop requested")
        
        # Stop the FastAPI server
        self.process_manager.stop()
        
        # Signal the main thread to exit
        win32event.SetEvent(self.hWaitStop)
        
        self.logger.info("Service stopped")
    
    def SvcDoRun(self):
        """Run the service."""
        servicemanager.LogMsg(
            servicemanager.EVENTLOG_INFORMATION_TYPE,
            servicemanager.PYS_SERVICE_STARTED,
            (self._svc_name_, '')
        )
        
        self.logger.info(f"Starting {self._svc_display_name_} service")
        
        try:
            # Start the FastAPI server
            if not self.process_manager.start():
                self.logger.critical("Failed to start FastAPI server, service will exit")
                return
            
            # Main service loop
            while True:
                # Wait for service stop signal or check interval
                result = win32event.WaitForSingleObject(self.hWaitStop, 5000)  # 5 second check interval
                
                # If stop signal received
                if result == win32event.WAIT_OBJECT_0:
                    break
                
                # Check process health
                if not self.process_manager.check_health():
                    self.logger.critical("FastAPI server is not healthy and cannot be restarted")
                    break
            
        except Exception as e:
            self.logger.critical(f"Service error: {str(e)}")
            
        finally:
            # Ensure process is stopped
            self.process_manager.stop()
            self.logger.info("Service run completed")


def run_debug_mode():
    """Run the server in debug mode (not as a service)."""
    print("Running in debug mode (press Ctrl+C to stop)...")
    
    config = ConfigManager()
    logger = ServiceLogger(config)
    process_manager = ProcessManager(config, logger)
    
    logger.info("Starting server in debug mode")
    
    try:
        if not process_manager.start():
            logger.critical("Failed to start server in debug mode")
            return
        
        logger.info("Server running in debug mode. Press Ctrl+C to stop.")
        
        # Main loop
        while process_manager.running:
            time.sleep(1)
            process_manager.check_health()
            
    except KeyboardInterrupt:
        logger.info("Keyboard interrupt received, stopping server")
    except Exception as e:
        logger.critical(f"Error in debug mode: {str(e)}")
    finally:
        process_manager.stop()
        logger.info("Debug mode stopped")


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1].lower() == "debug":
        run_debug_mode()
    else:
        win32serviceutil.HandleCommandLine(MCPServerService)
