<#
.SYNOPSIS
    Installs, updates, or uninstalls the MCP Terminal Server as a Windows service.

.DESCRIPTION
    This PowerShell script manages the MCP Terminal Server Windows service lifecycle.
    It can install, update, uninstall, and configure the service with various options.
    The script performs validation checks, handles errors gracefully, and provides
    detailed logging of all operations.

.PARAMETER Action
    The action to perform: Install, Update, Uninstall, or Start.
    Default is Install.

.PARAMETER InstallDir
    The directory where the service should be installed.
    Default is the script's directory.

.PARAMETER ApiKey
    API key for securing the server. If not provided, a random key will be generated.

.PARAMETER Port
    Port number for the server. Default is 8000.

.PARAMETER Host
    Host address to bind the server to. Default is 0.0.0.0 (all interfaces).

.PARAMETER LogLevel
    Log level (debug, info, warning, error, critical). Default is info.

.PARAMETER ConfigFile
    Path to a custom configuration file. If not provided, a default config will be created.

.PARAMETER ServiceName
    Name of the Windows service. Default is "MCP_Terminal_Server".

.PARAMETER ServiceDisplayName
    Display name of the Windows service. Default is "MCP Terminal Server".

.PARAMETER ServiceDescription
    Description of the Windows service. Default is "Runs a lightweight MCP server for live terminal commands."

.PARAMETER AutoStart
    Whether the service should start automatically on system boot. Default is true.

.PARAMETER PythonPath
    Path to the Python executable to use. If not provided, the script will use the system Python.

.PARAMETER PipArgs
    Additional arguments to pass to pip when installing dependencies.

.PARAMETER Force
    Force the operation without prompting for confirmation.

.PARAMETER LogToFile
    Enable logging to a file. Default is true.

.PARAMETER LogFile
    Path to the installation log file. Default is "install_service_log.txt" in the script directory.

.EXAMPLE
    .\install_service.ps1
    Installs the service with default settings.

.EXAMPLE
    .\install_service.ps1 -ApiKey "my-secret-key" -Port 8080 -Host "127.0.0.1" -LogLevel "debug"
    Installs the service with custom settings.

.EXAMPLE
    .\install_service.ps1 -Action Update -ConfigFile "C:\config\custom_config.json"
    Updates the service with a custom configuration file.

.EXAMPLE
    .\install_service.ps1 -Action Uninstall -Force
    Uninstalls the service without prompting for confirmation.

.NOTES
    Author: MCP Terminal Server Team
    Version: 2.0.0
    License: MIT
#>

[CmdletBinding()]
param (
    [ValidateSet("Install", "Update", "Uninstall", "Start")]
    [string]$Action = "Install",
    
    [string]$InstallDir = "",
    [string]$ApiKey = "",
    [int]$Port = 8000,
    [string]$Host = "0.0.0.0",
    
    [ValidateSet("debug", "info", "warning", "error", "critical")]
    [string]$LogLevel = "info",
    
    [string]$ConfigFile = "",
    [string]$ServiceName = "MCP_Terminal_Server",
    [string]$ServiceDisplayName = "MCP Terminal Server",
    [string]$ServiceDescription = "Runs a lightweight MCP server for live terminal commands.",
    [bool]$AutoStart = $true,
    [string]$PythonPath = "",
    [string]$PipArgs = "",
    [switch]$Force,
    [bool]$LogToFile = $true,
    [string]$LogFile = ""
)

#region Functions

function Write-LogMessage {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Message,
        
        [ValidateSet("INFO", "WARNING", "ERROR", "SUCCESS", "DEBUG")]
        [string]$Level = "INFO"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"
    
    # Output to console with color
    switch ($Level) {
        "INFO" { Write-Host $logMessage -ForegroundColor Cyan }
        "WARNING" { Write-Host $logMessage -ForegroundColor Yellow }
        "ERROR" { Write-Host $logMessage -ForegroundColor Red }
        "SUCCESS" { Write-Host $logMessage -ForegroundColor Green }
        "DEBUG" {
            if ($LogLevel -eq "debug") {
                Write-Host $logMessage -ForegroundColor Gray
            }
        }
    }
    
    # Write to log file if enabled
    if ($LogToFile -and $script:LogFilePath) {
        Add-Content -Path $script:LogFilePath -Value $logMessage -ErrorAction SilentlyContinue
    }
}

function Test-AdminPrivileges {
    $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) {
        Write-LogMessage "This script must be run as Administrator. Please restart PowerShell as Administrator and try again." -Level "ERROR"
        return $false
    }
    return $true
}

function Test-PythonInstallation {
    try {
        $pythonCommand = if ($PythonPath) { $PythonPath } else { "python" }
        $pythonVersion = & $pythonCommand --version 2>&1
        
        if ($LASTEXITCODE -ne 0) {
            Write-LogMessage "Python is not installed or not in PATH. Please install Python 3.7 or higher." -Level "ERROR"
            return $false
        }
        
        # Extract version number
        $versionMatch = $pythonVersion | Select-String -Pattern "Python (\d+\.\d+\.\d+)"
        if ($versionMatch) {
            $version = [Version]$versionMatch.Matches.Groups[1].Value
            if ($version -lt [Version]"3.7.0") {
                Write-LogMessage "Python version $version detected. Version 3.7.0 or higher is required." -Level "ERROR"
                return $false
            }
            
            Write-LogMessage "Python version $version detected." -Level "INFO"
            return $true
        }
        
        Write-LogMessage "Could not determine Python version. Please ensure Python 3.7 or higher is installed." -Level "WARNING"
        return $false
    }
    catch {
        Write-LogMessage "Error checking Python installation: $_" -Level "ERROR"
        return $false
    }
}

function Test-RequiredModules {
    try {
        $pythonCommand = if ($PythonPath) { $PythonPath } else { "python" }
        $pipCommand = if ($PythonPath) { "$PythonPath -m pip" } else { "pip" }
        
        # Check if pip is installed
        $pipCheck = & $pythonCommand -m pip --version 2>&1
        if ($LASTEXITCODE -ne 0) {
            Write-LogMessage "pip is not installed. Please install pip." -Level "ERROR"
            return $false
        }
        
        # Check for required modules
        $requiredModules = @("win32service", "fastapi", "uvicorn")
        $missingModules = @()
        
        foreach ($module in $requiredModules) {
            $moduleCheck = & $pythonCommand -c "import $($module.Replace('win32service', 'win32serviceutil'))" 2>&1
            if ($LASTEXITCODE -ne 0) {
                $missingModules += $module
            }
        }
        
        if ($missingModules.Count -gt 0) {
            Write-LogMessage "The following required modules are missing: $($missingModules -join ', ')" -Level "WARNING"
            Write-LogMessage "These will be installed during the installation process." -Level "INFO"
        } else {
            Write-LogMessage "All required Python modules are installed." -Level "SUCCESS"
        }
        
        return $true
    }
    catch {
        Write-LogMessage "Error checking required modules: $_" -Level "ERROR"
        return $false
    }
}

function Test-DiskSpace {
    param (
        [string]$Path,
        [int]$RequiredMB = 50
    )
    
    try {
        $drive = Split-Path -Qualifier $Path
        $driveInfo = Get-PSDrive -Name $drive.Replace(":", "")
        $freeSpaceMB = [math]::Round($driveInfo.Free / 1MB)
        
        if ($freeSpaceMB -lt $RequiredMB) {
            Write-LogMessage "Insufficient disk space on drive $drive. Required: $RequiredMB MB, Available: $freeSpaceMB MB" -Level "ERROR"
            return $false
        }
        
        Write-LogMessage "Sufficient disk space available on drive $drive: $freeSpaceMB MB" -Level "DEBUG"
        return $true
    }
    catch {
        Write-LogMessage "Error checking disk space: $_" -Level "ERROR"
        # Continue anyway, this is not critical
        return $true
    }
}

function New-ConfigurationFile {
    param (
        [string]$ConfigPath,
        [hashtable]$ConfigValues
    )
    
    try {
        # Create a basic config file
        $config = @{
            host = $ConfigValues.Host
            port = $ConfigValues.Port
            log_level = $ConfigValues.LogLevel
            log_file = "mcp_terminal_server.log"
            max_log_size_mb = 10
            log_backup_count = 5
            restart_on_failure = $true
            max_restart_attempts = 5
            restart_delay_seconds = 10
            shutdown_timeout_seconds = 30
            working_directory = $ConfigValues.WorkingDirectory
        }
        
        $config | ConvertTo-Json -Depth 10 | Set-Content -Path $ConfigPath
        Write-LogMessage "Created new configuration file: $ConfigPath" -Level "SUCCESS"
        return $true
    }
    catch {
        Write-LogMessage "Failed to create configuration file: $_" -Level "ERROR"
        return $false
    }
}

function Update-ConfigurationFile {
    param (
        [string]$ConfigPath,
        [hashtable]$ConfigValues
    )
    
    try {
        $config = Get-Content -Path $ConfigPath -Raw | ConvertFrom-Json
        
        # Update properties if provided
        if ($ConfigValues.ContainsKey("Host")) { $config.host = $ConfigValues.Host }
        if ($ConfigValues.ContainsKey("Port")) { $config.port = $ConfigValues.Port }
        if ($ConfigValues.ContainsKey("LogLevel")) { $config.log_level = $ConfigValues.LogLevel }
        if ($ConfigValues.ContainsKey("WorkingDirectory") -and $ConfigValues.WorkingDirectory) {
            $config.working_directory = $ConfigValues.WorkingDirectory
        }
        
        # Create backup of existing config
        $backupPath = "$ConfigPath.backup"
        Copy-Item -Path $ConfigPath -Destination $backupPath -Force
        Write-LogMessage "Created backup of existing configuration: $backupPath" -Level "DEBUG"
        
        # Save updated config
        $config | ConvertTo-Json -Depth 10 | Set-Content -Path $ConfigPath
        Write-LogMessage "Updated configuration file: $ConfigPath" -Level "SUCCESS"
        return $true
    }
    catch {
        Write-LogMessage "Failed to update configuration file: $_" -Level "ERROR"
        Write-LogMessage "Continuing with existing configuration." -Level "WARNING"
        return $false
    }
}

function Install-Dependencies {
    try {
        Write-LogMessage "Installing Python dependencies..." -Level "INFO"
        
        $pipCommand = if ($PythonPath) { "$PythonPath -m pip" } else { "pip" }
        $requirementsPath = Join-Path $script:WorkingDirectory "requirements.txt"
        
        if (-not (Test-Path $requirementsPath)) {
            Write-LogMessage "Requirements file not found: $requirementsPath" -Level "ERROR"
            return $false
        }
        
        $pipArgsList = @("install", "-r", $requirementsPath)
        if ($PipArgs) {
            $pipArgsList += $PipArgs.Split(" ")
        }
        
        $process = Start-Process -FilePath $pipCommand -ArgumentList $pipArgsList -NoNewWindow -Wait -PassThru
        
        if ($process.ExitCode -ne 0) {
            Write-LogMessage "Failed to install dependencies. Exit code: $($process.ExitCode)" -Level "ERROR"
            return $false
        }
        
        Write-LogMessage "Dependencies installed successfully." -Level "SUCCESS"
        return $true
    }
    catch {
        Write-LogMessage "Error installing dependencies: $_" -Level "ERROR"
        return $false
    }
}

function Install-WindowsService {
    try {
        Write-LogMessage "Installing Windows service: $ServiceName..." -Level "INFO"
        
        $pythonCommand = if ($PythonPath) { $PythonPath } else { "python" }
        $servicePyPath = Join-Path $script:WorkingDirectory "service.py"
        
        # Set environment variables for service configuration
        [System.Environment]::SetEnvironmentVariable("MCP_SERVICE_NAME", $ServiceName, [System.EnvironmentVariableTarget]::Machine)
        [System.Environment]::SetEnvironmentVariable("MCP_SERVICE_DISPLAY_NAME", $ServiceDisplayName, [System.EnvironmentVariableTarget]::Machine)
        [System.Environment]::SetEnvironmentVariable("MCP_SERVICE_DESCRIPTION", $ServiceDescription, [System.EnvironmentVariableTarget]::Machine)
        
        # Install the service
        $process = Start-Process -FilePath $pythonCommand -ArgumentList "$servicePyPath install" -NoNewWindow -Wait -PassThru
        
        if ($process.ExitCode -ne 0) {
            Write-LogMessage "Failed to install the service. Exit code: $($process.ExitCode)" -Level "ERROR"
            return $false
        }
        
        # Configure service startup type
        if ($AutoStart) {
            $startupType = "Automatic"
        } else {
            $startupType = "Manual"
        }
        
        Set-Service -Name $ServiceName -StartupType $startupType
        Write-LogMessage "Service startup type set to $startupType" -Level "INFO"
        
        Write-LogMessage "Service installed successfully." -Level "SUCCESS"
        return $true
    }
    catch {
        Write-LogMessage "Error installing service: $_" -Level "ERROR"
        return $false
    }
}

function Start-WindowsService {
    try {
        Write-LogMessage "Starting Windows service: $ServiceName..." -Level "INFO"
        
        $pythonCommand = if ($PythonPath) { $PythonPath } else { "python" }
        $servicePyPath = Join-Path $script:WorkingDirectory "service.py"
        
        # Start the service
        $process = Start-Process -FilePath $pythonCommand -ArgumentList "$servicePyPath start" -NoNewWindow -Wait -PassThru
        
        if ($process.ExitCode -ne 0) {
            Write-LogMessage "Failed to start the service. Exit code: $($process.ExitCode)" -Level "ERROR"
            return $false
        }
        
        # Verify service is running
        Start-Sleep -Seconds 3  # Give the service time to start
        $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
        
        if ($service -and $service.Status -eq "Running") {
            Write-LogMessage "Service started successfully." -Level "SUCCESS"
            return $true
        } else {
            Write-LogMessage "Service is not running after start command." -Level "ERROR"
            return $false
        }
    }
    catch {
        Write-LogMessage "Error starting service: $_" -Level "ERROR"
        return $false
    }
}

function Stop-WindowsService {
    try {
        Write-LogMessage "Stopping Windows service: $ServiceName..." -Level "INFO"
        
        $pythonCommand = if ($PythonPath) { $PythonPath } else { "python" }
        $servicePyPath = Join-Path $script:WorkingDirectory "service.py"
        
        # Stop the service
        $process = Start-Process -FilePath $pythonCommand -ArgumentList "$servicePyPath stop" -NoNewWindow -Wait -PassThru
        
        # Give the service time to stop
        Start-Sleep -Seconds 3
        
        # Verify service is stopped
        $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
        
        if ($service -and $service.Status -eq "Stopped") {
            Write-LogMessage "Service stopped successfully." -Level "SUCCESS"
            return $true
        } else {
            Write-LogMessage "Service could not be stopped. Attempting to force stop..." -Level "WARNING"
            
            # Try to force stop using Stop-Service
            Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
            Start-Sleep -Seconds 2
            
            $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
            if ($service -and $service.Status -eq "Stopped") {
                Write-LogMessage "Service force-stopped successfully." -Level "SUCCESS"
                return $true
            } else {
                Write-LogMessage "Failed to stop the service." -Level "ERROR"
                return $false
            }
        }
    }
    catch {
        Write-LogMessage "Error stopping service: $_" -Level "ERROR"
        return $false
    }
}

function Uninstall-WindowsService {
    try {
        Write-LogMessage "Uninstalling Windows service: $ServiceName..." -Level "INFO"
        
        # First stop the service if it's running
        $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
        if ($service) {
            if ($service.Status -eq "Running") {
                Stop-WindowsService
            }
            
            $pythonCommand = if ($PythonPath) { $PythonPath } else { "python" }
            $servicePyPath = Join-Path $script:WorkingDirectory "service.py"
            
            # Remove the service
            $process = Start-Process -FilePath $pythonCommand -ArgumentList "$servicePyPath remove" -NoNewWindow -Wait -PassThru
            
            if ($process.ExitCode -ne 0) {
                Write-LogMessage "Failed to remove the service. Exit code: $($process.ExitCode)" -Level "ERROR"
                return $false
            }
            
            # Clean up environment variables
            [System.Environment]::SetEnvironmentVariable("MCP_TERMINAL_API_KEY", $null, [System.EnvironmentVariableTarget]::Machine)
            [System.Environment]::SetEnvironmentVariable("MCP_SERVICE_NAME", $null, [System.EnvironmentVariableTarget]::Machine)
            [System.Environment]::SetEnvironmentVariable("MCP_SERVICE_DISPLAY_NAME", $null, [System.EnvironmentVariableTarget]::Machine)
            [System.Environment]::SetEnvironmentVariable("MCP_SERVICE_DESCRIPTION", $null, [System.EnvironmentVariableTarget]::Machine)
            
            Write-LogMessage "Service uninstalled successfully." -Level "SUCCESS"
            return $true
        } else {
            Write-LogMessage "Service not found. Nothing to uninstall." -Level "WARNING"
            return $true
        }
    }
    catch {
        Write-LogMessage "Error uninstalling service: $_" -Level "ERROR"
        return $false
    }
}

function Update-WindowsService {
    try {
        Write-LogMessage "Updating Windows service: $ServiceName..." -Level "INFO"
        
        # Check if service exists
        $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
        if (-not $service) {
            Write-LogMessage "Service not found. Cannot update." -Level "ERROR"
            return $false
        }
        
        # Stop the service
        $serviceWasRunning = $service.Status -eq "Running"
        if ($serviceWasRunning) {
            Stop-WindowsService
        }
        
        # Update dependencies
        Install-Dependencies
        
        # Update configuration
        if ($ConfigFile) {
            $configPath = if ([System.IO.Path]::IsPathRooted($ConfigFile)) { $ConfigFile } else { Join-Path $script:WorkingDirectory $ConfigFile }
        } else {
            $configPath = Join-Path $script:WorkingDirectory "config.json"
        }
        
        $configValues = @{
            Host = $Host
            Port = $Port
            LogLevel = $LogLevel
            WorkingDirectory = $script:WorkingDirectory
        }
        
        if (Test-Path $configPath) {
            Update-ConfigurationFile -ConfigPath $configPath -ConfigValues $configValues
        } else {
            New-ConfigurationFile -ConfigPath $configPath -ConfigValues $configValues
        }
        
        # Update service
        $pythonCommand = if ($PythonPath) { $PythonPath } else { "python" }
        $servicePyPath = Join-Path $script:WorkingDirectory "service.py"
        
        $process = Start-Process -FilePath $pythonCommand -ArgumentList "$servicePyPath update" -NoNewWindow -Wait -PassThru
        
        # Restart the service if it was running
        if ($serviceWasRunning) {
            Start-WindowsService
        }
        
        Write-LogMessage "Service updated successfully." -Level "SUCCESS"
        return $true
    }
    catch {
        Write-LogMessage "Error updating service: $_" -Level "ERROR"
        return $false
    }
}

function Show-ServiceStatus {
    try {
        $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
        if ($service) {
            $status = $service.Status
            $startType = $service.StartType
            
            Write-LogMessage "Service Status:" -Level "INFO"
            Write-LogMessage "  Name: $ServiceName" -Level "INFO"
            Write-LogMessage "  Display Name: $ServiceDisplayName" -Level "INFO"
            Write-LogMessage "  Status: $status" -Level "INFO"
            Write-LogMessage "  Start Type: $startType" -Level "INFO"
            
            if ($status -eq "Running") {
                Write-LogMessage "  URL: http://$Host`:$Port" -Level "INFO"
                
                # Get API key from environment variable
                $apiKey = [System.Environment]::GetEnvironmentVariable("MCP_TERMINAL_API_KEY", [System.EnvironmentVariableTarget]::Machine)
                if ($apiKey) {
                    Write-LogMessage "  API Key: $apiKey" -Level "INFO"
                }
                
                Write-LogMessage "`nTo test the server, run: python test_client.py -k $apiKey" -Level "INFO"
            }
        } else {
            Write-LogMessage "Service not found: $ServiceName" -Level "WARNING"
        }
    }
    catch {
        Write-LogMessage "Error getting service status: $_" -Level "ERROR"
    }
}

function Show-HelpInformation {
    Write-LogMessage "`nAdditional commands:" -Level "INFO"
    Write-LogMessage "  - Run in debug mode: python service.py debug" -Level "INFO"
    Write-LogMessage "  - Stop service: python service.py stop" -Level "INFO"
    Write-LogMessage "  - Restart service: python service.py restart" -Level "INFO"
    Write-LogMessage "  - Remove service: python service.py remove" -Level "INFO"
    Write-LogMessage "  - Update service: python service.py update" -Level "INFO"
    Write-LogMessage "`nFor more information, see the README.md file." -Level "INFO"
}

#endregion Functions

# Set error action preference
$ErrorActionPreference = "Stop"

# Initialize script variables
$script:StartTime = Get-Date
$script:ScriptPath = Split-Path -Parent $MyInvocation.MyCommand.Path

# Set working directory
if (-not $InstallDir) {
    $script:WorkingDirectory = $script:ScriptPath
} else {
    if ([System.IO.Path]::IsPathRooted($InstallDir)) {
        $script:WorkingDirectory = $InstallDir
    } else {
        $script:WorkingDirectory = Join-Path $script:ScriptPath $InstallDir
    }
    
    # Create directory if it doesn't exist
    if (-not (Test-Path $script:WorkingDirectory)) {
        New-Item -Path $script:WorkingDirectory -ItemType Directory -Force | Out-Null
    }
}

# Set log file path
if (-not $LogFile) {
    $script:LogFilePath = Join-Path $script:WorkingDirectory "install_service_log.txt"
} else {
    if ([System.IO.Path]::IsPathRooted($LogFile)) {
        $script:LogFilePath = $LogFile
    } else {
        $script:LogFilePath = Join-Path $script:WorkingDirectory $LogFile
    }
}

# Create log directory if it doesn't exist
$logDir = Split-Path -Parent $script:LogFilePath
if (-not (Test-Path $logDir)) {
    New-Item -Path $logDir -ItemType Directory -Force | Out-Null
}

# Check if running as administrator
if (-not (Test-AdminPrivileges)) {
    exit 1
}

try {
    # Start logging
    Write-LogMessage "=== MCP Terminal Server Installation Script ===" -Level "INFO"
    Write-LogMessage "Started at: $script:StartTime" -Level "INFO"
    Write-LogMessage "Action: $Action" -Level "INFO"
    Write-LogMessage "Working Directory: $script:WorkingDirectory" -Level "INFO"
    Write-LogMessage "Log File: $script:LogFilePath" -Level "INFO"
    
    # Change to working directory
    Set-Location $script:WorkingDirectory
    Write-LogMessage "Changed working directory to: $script:WorkingDirectory" -Level "DEBUG"
    
    # Perform validation checks
    $validationPassed = $true
    
    # Check Python installation
    if (-not (Test-PythonInstallation)) {
        $validationPassed = $false
        throw "Python validation failed."
    }
    
    # Check required modules
    if (-not (Test-RequiredModules)) {
        Write-LogMessage "Some required modules are missing but will be installed." -Level "WARNING"
    }
    
    # Check disk space
    if (-not (Test-DiskSpace -Path $script:WorkingDirectory)) {
        $validationPassed = $false
        throw "Disk space validation failed."
    }
    
    # If validation failed, exit
    if (-not $validationPassed) {
        throw "Validation checks failed. Please fix the issues and try again."
    }
    
    # Perform the requested action
    switch ($Action) {
        "Install" {
            Write-LogMessage "Installing MCP Terminal Server..." -Level "INFO"
            
            # Generate a random API key if not provided
            if (-not $ApiKey) {
                $ApiKey = [System.Guid]::NewGuid().ToString("N")
                Write-LogMessage "Generated random API key: $ApiKey" -Level "WARNING"
                Write-LogMessage "Please save this key for client authentication!" -Level "WARNING"
            }
            
            # Set API key as environment variable
            [System.Environment]::SetEnvironmentVariable("MCP_TERMINAL_API_KEY", $ApiKey, [System.EnvironmentVariableTarget]::Machine)
            Write-LogMessage "API key set as system environment variable 'MCP_TERMINAL_API_KEY'" -Level "SUCCESS"
            
            # Create or update configuration
            if (-not $ConfigFile) {
                $ConfigFile = Join-Path $script:WorkingDirectory "config.json"
            } else {
                if (-not [System.IO.Path]::IsPathRooted($ConfigFile)) {
                    $ConfigFile = Join-Path $script:WorkingDirectory $ConfigFile
                }
            }
            
            # Check if config file exists, if not create it from sample
            $sampleConfigFile = Join-Path $script:WorkingDirectory "config.json.sample"
            if (-not (Test-Path $ConfigFile)) {
                if (Test-Path $sampleConfigFile) {
                    Copy-Item $sampleConfigFile $ConfigFile
                    Write-LogMessage "Created configuration file from sample: $ConfigFile" -Level "SUCCESS"
                    
                    # Update the config with provided parameters
                    $configValues = @{
                        Host = $Host
                        Port = $Port
                        LogLevel = $LogLevel
                        WorkingDirectory = $script:WorkingDirectory
                    }
                    Update-ConfigurationFile -ConfigPath $ConfigFile -ConfigValues $configValues
                } else {
                    # Create a new config file
                    $configValues = @{
                        Host = $Host
                        Port = $Port
                        LogLevel = $LogLevel
                        WorkingDirectory = $script:WorkingDirectory
                    }
                    New-ConfigurationFile -ConfigPath $ConfigFile -ConfigValues $configValues
                }
            } else {
                # Update existing config with new parameters
                $configValues = @{
                    Host = $Host
                    Port = $Port
                    LogLevel = $LogLevel
                    WorkingDirectory = $script:WorkingDirectory
                }
                Update-ConfigurationFile -ConfigPath $ConfigFile -ConfigValues $configValues
            }
            
            # Install dependencies
            if (-not (Install-Dependencies)) {
                throw "Failed to install dependencies."
            }
            
            # Check if service is already installed
            $serviceExists = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
            
            if ($serviceExists) {
                # Confirm service replacement if not forced
                if (-not $Force) {
                    Write-LogMessage "Service '$ServiceName' already exists." -Level "WARNING"
                    $confirmation = Read-Host "Do you want to replace it? (Y/N)"
                    if ($confirmation -ne "Y" -and $confirmation -ne "y") {
                        throw "Installation cancelled by user."
                    }
                }
                
                # Stop and remove existing service
                if (-not (Stop-WindowsService)) {
                    Write-LogMessage "Failed to stop existing service. Attempting to continue anyway." -Level "WARNING"
                }
                
                if (-not (Uninstall-WindowsService)) {
                    throw "Failed to remove existing service."
                }
            }
            
            # Install the service
            if (-not (Install-WindowsService)) {
                throw "Failed to install the service."
            }
            
            # Start the service
            if (-not (Start-WindowsService)) {
                Write-LogMessage "Failed to start the service. You may need to start it manually." -Level "WARNING"
            }
            
            # Show service status
            Show-ServiceStatus
            
            # Show help information
            Show-HelpInformation
            
            Write-LogMessage "Installation completed successfully." -Level "SUCCESS"
        }
        
        "Update" {
            Write-LogMessage "Updating MCP Terminal Server..." -Level "INFO"
            
            # Update the service
            if (-not (Update-WindowsService)) {
                throw "Failed to update the service."
            }
            
            # Show service status
            Show-ServiceStatus
            
            Write-LogMessage "Update completed successfully." -Level "SUCCESS"
        }
        
        "Uninstall" {
            Write-LogMessage "Uninstalling MCP Terminal Server..." -Level "INFO"
            
            # Confirm uninstallation if not forced
            if (-not $Force) {
                $confirmation = Read-Host "Are you sure you want to uninstall the service? (Y/N)"
                if ($confirmation -ne "Y" -and $confirmation -ne "y") {
                    throw "Uninstallation cancelled by user."
                }
            }
            
            # Uninstall the service
            if (-not (Uninstall-WindowsService)) {
                throw "Failed to uninstall the service."
            }
            
            Write-LogMessage "Uninstallation completed successfully." -Level "SUCCESS"
        }
        
        "Start" {
            Write-LogMessage "Starting MCP Terminal Server..." -Level "INFO"
            
            # Start the service
            if (-not (Start-WindowsService)) {
                throw "Failed to start the service."
            }
            
            # Show service status
            Show-ServiceStatus
            
            Write-LogMessage "Service started successfully." -Level "SUCCESS"
        }
    }
    
} catch {
    Write-LogMessage "An error occurred: $_" -Level "ERROR"
    exit 1
} finally {
    Write-LogMessage "Script execution completed at: $(Get-Date)" -Level "INFO"
    Write-LogMessage "Total execution time: $([math]::Round(((Get-Date) - $script:StartTime).TotalSeconds, 2)) seconds" -Level "INFO"
}
