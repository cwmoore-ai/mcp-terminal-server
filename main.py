"""
MCP Terminal Server - FastAPI Server for Windows Command Execution

This module provides a FastAPI server that can run as a Windows service and
exposes an endpoint to execute shell commands and stream their output.
"""

import asyncio
import logging
import os
import re
import uuid
from enum import Enum
from typing import AsyncGenerator, Dict, List, Optional, Set, Union

import uvicorn
from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from fastapi.security import APIKeyHeader
from pydantic import BaseModel, Field, validator
from starlette.concurrency import iterate_in_threadpool

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler("terminal_server.log"),
    ],
)
logger = logging.getLogger("mcp-terminal-server")

# Get API key from environment variable or use a default for development
API_KEY = os.environ.get("MCP_TERMINAL_API_KEY", "dev-api-key-change-me-in-production")
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)

# Define dangerous command patterns to block
DANGEROUS_PATTERNS = [
    r"rm\s+-rf\s+/",  # Remove root directory
    r"format\s+[a-zA-Z]:/?",  # Format drives
    r"del\s+/[fqs]\s+[a-zA-Z]:/?",  # Delete drive contents
    r"rd\s+/[sq]\s+[a-zA-Z]:/?",  # Remove directory recursively
    r"shutdown",  # Shutdown commands
    r"taskkill\s+/f\s+/im\s+system",  # Kill system processes
]

# Mapping session IDs to running processes
running_sessions: Dict[str, asyncio.subprocess.Process] = {}

# Rate limiting: track requests per IP
request_counts: Dict[str, int] = {}
MAX_REQUESTS_PER_MINUTE = 30
RATE_LIMIT_RESET_INTERVAL = 60  # seconds

class OutputSource(str, Enum):
    """Enum to identify the source of command output."""
    STDOUT = "stdout"
    STDERR = "stderr"
    SYSTEM = "system"  # For system messages

class OutputLine(BaseModel):
    """Model for a line of output from a command."""
    source: OutputSource
    content: str

class CommandRequest(BaseModel):
    """Model for the command execution request."""
    command: str = Field(..., description="The command to execute")
    
    @validator("command")
    def validate_command(cls, command: str) -> str:
        """Validate that the command is not dangerous."""
        # Check against dangerous patterns
        for pattern in DANGEROUS_PATTERNS:
            if re.search(pattern, command, re.IGNORECASE):
                raise ValueError(f"Command contains potentially dangerous pattern: {pattern}")
        return command

class CommandResponse(BaseModel):
    """Model for the command execution response."""
    session_id: str
    status: str
    message: str

# Create FastAPI app with metadata for documentation
app = FastAPI(
    title="MCP Terminal Server",
    description="A FastAPI server that executes Windows shell commands and streams their output",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Restrict in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

async def verify_api_key(api_key: str = Depends(api_key_header)):
    """Verify the API key."""
    if api_key != API_KEY:
        logger.warning(f"Invalid API key attempt")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key",
        )
    return api_key

@app.middleware("http")
async def rate_limit_middleware(request: Request, call_next):
    """Middleware to implement rate limiting."""
    client_ip = request.client.host
    
    # Skip rate limiting for documentation
    if request.url.path in ["/docs", "/redoc", "/openapi.json"]:
        return await call_next(request)
    
    # Increment request count for this IP
    if client_ip in request_counts:
        request_counts[client_ip] += 1
    else:
        request_counts[client_ip] = 1
    
    # Check if rate limit exceeded
    if request_counts.get(client_ip, 0) > MAX_REQUESTS_PER_MINUTE:
        logger.warning(f"Rate limit exceeded for IP: {client_ip}")
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Rate limit exceeded. Try again later.",
        )
    
    # Process the request
    response = await call_next(request)
    
    return response

# Schedule task to reset rate limits
@app.on_event("startup")
async def setup_rate_limit_reset():
    """Set up periodic reset of rate limits."""
    async def reset_rate_limits():
        while True:
            await asyncio.sleep(RATE_LIMIT_RESET_INTERVAL)
            request_counts.clear()
            logger.debug("Rate limit counters reset")
    
    # Start the background task
    asyncio.create_task(reset_rate_limits())

async def stream_command(session_id: str, cmd: str) -> AsyncGenerator[str, None]:
    """
    Execute a command and stream its output.
    
    Args:
        session_id: Unique identifier for this command execution
        cmd: The command to execute
        
    Yields:
        Lines of output from the command (stdout and stderr)
    """
    try:
        logger.info(f"Executing command: {cmd} (session: {session_id})")
        
        # Create subprocess
        process = await asyncio.create_subprocess_shell(
            cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        
        # Store process for potential future control
        running_sessions[session_id] = process
        
        # Yield a system message indicating command start
        yield f"[SYSTEM] Started command execution: {cmd}\n"
        
        # Create tasks to read from stdout and stderr simultaneously
        async def read_stream(stream, source):
            while True:
                line = await stream.readline()
                if not line:
                    break
                prefix = "[STDERR] " if source == OutputSource.STDERR else ""
                yield f"{prefix}{line.decode().strip()}\n"
        
        # Create tasks for reading both streams
        stdout_task = asyncio.create_task(read_stream(process.stdout, OutputSource.STDOUT))
        stderr_task = asyncio.create_task(read_stream(process.stderr, OutputSource.STDERR))
        
        # Process output from both streams as it becomes available
        pending = {stdout_task, stderr_task}
        while pending:
            done, pending = await asyncio.wait(
                pending, 
                return_when=asyncio.FIRST_COMPLETED
            )
            
            for task in done:
                try:
                    async for line in task.result():
                        yield line
                except Exception as e:
                    logger.error(f"Error processing stream: {str(e)}")
                    yield f"[SYSTEM] Error processing output: {str(e)}\n"
        
        # Wait for process to complete
        return_code = await process.wait()
        yield f"[SYSTEM] Command completed with return code: {return_code}\n"
        
        if return_code != 0:
            logger.warning(f"Command exited with non-zero code: {return_code} (session: {session_id})")
        else:
            logger.info(f"Command completed successfully (session: {session_id})")
            
    except asyncio.CancelledError:
        # Handle cancellation (e.g., client disconnected)
        logger.info(f"Command execution cancelled (session: {session_id})")
        yield "[SYSTEM] Command execution cancelled\n"
        raise
        
    except Exception as e:
        # Handle other exceptions
        error_msg = f"Error executing command: {str(e)}"
        logger.error(f"{error_msg} (session: {session_id})")
        yield f"[SYSTEM] {error_msg}\n"
        
    finally:
        # Clean up finished session
        if session_id in running_sessions:
            process = running_sessions.pop(session_id)
            # Ensure process is terminated if it's still running
            if process.returncode is None:
                try:
                    process.terminate()
                    logger.info(f"Terminated process for session: {session_id}")
                except Exception as e:
                    logger.error(f"Error terminating process: {str(e)}")

@app.post(
    "/run", 
    response_model=None,
    summary="Execute a shell command",
    description="Executes a shell command and streams the output back to the client",
    response_description="Text stream of command output",
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(verify_api_key)]
)
async def run_command(request: CommandRequest):
    """
    Execute a shell command and stream the output.
    
    Args:
        request: The command request containing the command to execute
        
    Returns:
        A streaming response with the command output
    """
    session_id = str(uuid.uuid4())
    
    try:
        # Create the stream
        stream = stream_command(session_id, request.command)
        
        # Return streaming response
        return StreamingResponse(
            stream, 
            media_type="text/plain",
            headers={"X-Session-ID": session_id}
        )
        
    except Exception as e:
        logger.error(f"Error in run_command endpoint: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to execute command: {str(e)}"
        )

@app.get(
    "/health",
    summary="Health check endpoint",
    description="Returns the health status of the server",
    response_description="Health status",
    status_code=status.HTTP_200_OK
)
async def health_check():
    """Health check endpoint."""
    return {"status": "healthy", "active_sessions": len(running_sessions)}

if __name__ == "__main__":
    # Run the server when executed directly
    uvicorn.run(app, host="127.0.0.1", port=8000)
