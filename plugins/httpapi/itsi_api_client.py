# (c) 2025 Splunk ITSI Ansible Collection maintainers
# GPL-3.0-or-later

from __future__ import annotations

__metaclass__ = type

DOCUMENTATION = r"""
---
author: "splunk.itsi maintainers"
name: itsi_api_client
short_description: HttpApi Plugin for Splunk ITSI
description:
  - Provides a persistent HTTP(S) connection and authentication for the Splunk ITSI REST API.
  - Modules call C(conn.send_request(path, data, method="GET")) and this plugin injects authentication and JSON headers.
  - Returns response format with status, headers, and body structure for full HTTP metadata access.
  - Automatically adds C(output_mode=json) to GET requests for consistent JSON responses from Splunk.
  - Compatible with both core httpapi and ansible.netcommon.httpapi connections for advanced features.
version_added: "1.0.0"
options:
  token:
    description: 
      - Pre-created Splunk authentication token to be sent as C(Authorization Bearer <token>).
      - Use for direct endpoint access with Splunk authentication tokens (Splunk Enterprise 7.3+).
      - These tokens must be created in Splunk and have token authentication enabled.
      - This is the highest priority authentication method.
    type: str
    no_log: true
    vars:
      - name: ansible_httpapi_token
  session_key:
    description: 
      - Pre-created Splunk session key from C(/services/auth/login) to be sent as C(Authorization Splunk <sessionKey>).
      - Use when you have already obtained a session key through external means.
      - If this authentication fails with 401, the plugin will automatically fallback to auto-retrieved session key.
    type: str
    no_log: true
    vars:
      - name: ansible_httpapi_session_key
  remote_user:
    description:
      - Username for Splunk authentication.
      - Used for auto-retrieved session key authentication via C(/services/auth/login) endpoint.
      - Also used as fallback for Basic authentication if session key retrieval fails.
      - When combined with password, enables automatic session key management with caching and refresh.
    type: str
    vars:
      - name: ansible_user
  password:
    description:
      - Password for Splunk authentication.
      - Used with remote_user for auto-retrieved session key authentication.
      - Also used as fallback for Basic authentication if session key retrieval fails.
      - Session keys obtained this way are automatically cached and refreshed on 401 errors.
    type: str
    no_log: true
    vars:
      - name: ansible_httpapi_pass
notes:
  - Basic configuration requires C(ansible_connection=httpapi) and C(ansible_network_os=splunk.itsi.itsi_api_client).
  - Advanced configuration uses C(ansible_connection=ansible.netcommon.httpapi) for proxy, SSL certs, timeouts, and connection persistence.
  - Always returns enhanced response format with structure containing status code, headers dict, and body string.
  - Authentication methods tried in priority order are Bearer token, explicit session key, auto-retrieved session key, Basic auth.
  - Auto-retrieved session keys are obtained via C(/services/auth/login) using remote_user and password credentials.
  - Session keys are automatically cached per connection instance and refreshed on 401 Unauthorized errors.
  - If explicit session_key fails with 401, the plugin will fallback to auto-retrieved session key if credentials are available.
  - Basic authentication is used as final fallback when session key methods are not available or fail.
  - Response body text has leading/trailing whitespace stripped by default for clean JSON parsing.
"""

EXAMPLES = r"""
# Basic HTTP API Configuration (Core Ansible)
[splunk]
splunk.example.com

[splunk:vars]
ansible_connection=httpapi
ansible_network_os=splunk.itsi.itsi_api_client
ansible_httpapi_use_ssl=true
ansible_httpapi_port=8089
ansible_httpapi_validate_certs=false

# Advanced HTTP API Configuration (ansible.netcommon.httpapi)
# Provides proxy support, client certificates, custom timeouts, connection persistence
[splunk_advanced]
splunk-enterprise.example.com

[splunk_advanced:vars]
ansible_connection=ansible.netcommon.httpapi
ansible_network_os=splunk.itsi.itsi_api_client
ansible_httpapi_use_ssl=true
ansible_httpapi_port=8089
ansible_httpapi_validate_certs=true
ansible_httpapi_ca_path=/etc/ssl/certs/ca-bundle.crt
ansible_httpapi_client_cert=/path/to/client.pem
ansible_httpapi_client_key=/path/to/client-key.pem
ansible_httpapi_use_proxy=true
ansible_httpapi_http_agent="SplunkITSI-Ansible/1.0.0"
ansible_command_timeout=60
ansible_connect_timeout=30

# Choose one auth method for either configuration:

# Method 1: Bearer Token (highest priority)
# ansible_httpapi_token=eyJraWQiOiJzcGx1bmsuc2VjcmV0IiwiYWxnIjoiSFM1MTIi...

# Method 2: Pre-created Session Key
# ansible_httpapi_session_key=192fd3e470d2b0cc...

# Method 3: Auto-retrieved Session Key (recommended for username/password)
# ansible_user=admin
# ansible_httpapi_pass=secret
# (Plugin automatically calls /services/auth/login, caches and refreshes session key)

# Method 4: Basic Auth (fallback)
# ansible_user=admin
# ansible_httpapi_pass=secret
# (Used only if session key retrieval fails)
"""

import base64
import json
from ansible.plugins.httpapi import HttpApiBase

BASE_HEADERS = {
    "Accept": "application/json",
    "Content-Type": "application/json",
}


class HttpApi(HttpApiBase):
    """HttpApi plugin for Splunk ITSI with token/session_key/basic auth and JSON defaults.
    
    Compatible with both core httpapi and ansible.netcommon.httpapi connections.
    """

    def __init__(self, *args, **kwargs):
        """Initialize per-instance authentication cache.
        
        Compatible with both core httpapi and ansible.netcommon.httpapi constructors.
        """
        # Call parent constructor with all provided arguments
        super().__init__(*args, **kwargs)
        
        # Store connection reference if provided (for netcommon compatibility)
        self._connection = args[0] if args else kwargs.get('connection')
        
        # Authentication cache to avoid repeated logins (instance-level attributes)
        self._cached_session_key = None
        self._cached_auth_headers = None
        self._auth_retry_attempted = False  # Track if we've already tried refresh
        self._auth_method = None  # Track which auth method we're using
        self._fallback_to_auto_session = False  # Flag for explicit session_key 401 fallback
    
    def logout(self):
        """Logout method for ansible.netcommon.httpapi compatibility."""
        # Clear cached authentication on logout
        self._clear_auth_cache()
    
    def handle_httperror(self, exc):
        """Handle HTTP errors for ansible.netcommon.httpapi compatibility.
        
        Returns:
        - True: Retry the request once with refreshed authentication
        - False: Raise the original exception
        - Response-like object: Use this as the response
        """
        # Check if this is a 401 Unauthorized and we haven't already tried refresh
        if hasattr(exc, 'code') and exc.code == 401:
            if not self._auth_retry_attempted and self._auth_method in ['session_key', 'auto_session']:
                self.connection.queue_message("vvv", f"ITSI HttpApi: 401 detected, attempting auth refresh")
                
                # Mark that we've attempted refresh to prevent infinite loops
                self._auth_retry_attempted = True
                
                # For explicit session_key that fails, try to fallback to auto-login if possible
                if self._auth_method == 'session_key':
                    try:
                        user = self.connection.get_option("remote_user")
                        password = self.connection.get_option("password")
                        if user and password:
                            self.connection.queue_message("vvv", f"ITSI HttpApi: Explicit session_key failed, falling back to auto-login")
                            self._fallback_to_auto_session = True
                    except (KeyError, Exception):
                        pass
                
                # Clear cached auth and force refresh
                self._clear_auth_cache()
                
                # Return True to retry the request with refreshed auth
                return True
            else:
                self.connection.queue_message("vvv", f"ITSI HttpApi: 401 after refresh attempt or non-session auth, propagating error")
                # Second 401 or non-session auth - propagate the error
                return False
        
        # For non-401 errors, don't retry
        return False
    
    def update_auth(self, response, response_text):
        """Update authentication tokens for ansible.netcommon.httpapi compatibility.
        
        Args:
            response: HTTP response object
            response_text: Response text content
            
        Returns:
            dict: New authentication headers or None
        """
        # Reset retry flag on successful response
        if hasattr(response, 'status') and 200 <= response.status < 300:
            self._auth_retry_attempted = False
        
        # ITSI doesn't provide auth token refresh in responses
        # Authentication refresh is handled in handle_httperror()
        return None

    def _clear_auth_cache(self):
        """Clear cached authentication data."""
        self.connection.queue_message("vvv", f"ITSI HttpApi: Clearing authentication cache")
        self._cached_session_key = None
        self._cached_auth_headers = None

    def _extract_status_headers_text(self, resp, strip_whitespace=True):
        """Extract HTTP status, headers, and body text from response.
        
        Args:
            resp: Response from connection.send() - format varies by connection type
            strip_whitespace: If True, strip leading/trailing whitespace from response body
            
        Returns:
            tuple: (status_code, headers_dict, response_text)
        """
        status = None
        headers_map = {}
        
        # netcommon: (response, buffer)
        if isinstance(resp, tuple) and len(resp) == 2:
            meta, _ = resp
            # status extraction across variants
            status = (
                getattr(meta, "status", None)
                or getattr(meta, "code", None)
                or (callable(getattr(meta, "getcode", None)) and meta.getcode())
            )
            # headers normalization
            raw_headers = getattr(meta, "headers", None) or getattr(meta, "msg", None)
            try:
                if raw_headers and hasattr(raw_headers, 'items'):
                    # HTTPMessage-like: use .items() to build a dict of str->str
                    headers_map = {str(k): str(v) for k, v in raw_headers.items()}
            except Exception:
                headers_map = {}
        
        text = self._handle_response(resp, strip_whitespace=strip_whitespace)
        # fall back to 200 if transport doesn't expose status
        return (int(status) if status is not None else 200), headers_map, text

    def _ensure_output_mode_json(self, path: str, method: str) -> str:
        """Ensure JSON output mode for GET requests."""
        if method == "GET" and "output_mode=" not in path:
            sep = "&" if "?" in path else "?"
            path = f"{path}{sep}output_mode=json"
        return path

    def _get_session_key(self, username: str, password: str, force_refresh: bool = False) -> str:
        """Get Splunk session key using /services/auth/login endpoint.
        
        Args:
            username: Splunk username
            password: Splunk password  
            force_refresh: If True, bypass cache and get new session key
            
        Returns:
            str: Session key or empty string if failed
        """
        # Return cached session key unless force refresh
        if not force_refresh and self._cached_session_key:
            self.connection.queue_message("vvv", f"ITSI HttpApi: Using cached session key")
            return self._cached_session_key
        
        try:
            import urllib.parse
            import xml.etree.ElementTree as ET
            
            self.connection.queue_message("vvv", f"ITSI HttpApi: Attempting to get session key for user: {username} (force_refresh={force_refresh})")
            
            # Prepare login data
            login_data = urllib.parse.urlencode({
                'username': username,
                'password': password
            }).encode('utf-8')
            
            # Login request Basic headers
            login_headers = {
                'Content-Type': 'application/x-www-form-urlencoded',
                'Accept': 'application/xml'
            }
            
            # Get session key via /services/auth/login
            response = self.connection.send('/services/auth/login', login_data, method='POST', headers=login_headers)
            
            # Extract response content
            if isinstance(response, tuple) and len(response) == 2:
                _, buffer = response
                response_text = buffer.getvalue() if hasattr(buffer, 'getvalue') else str(buffer)  # type: ignore
            elif hasattr(response, 'getvalue'):
                response_text = response.getvalue()  # type: ignore
            elif isinstance(response, (str, bytes)):
                response_text = response.decode('utf-8') if isinstance(response, bytes) else response
            else:
                response_text = str(response)
            
            # Parse XML response to extract session key
            root = ET.fromstring(response_text)
            session_key_elem = root.find('.//sessionKey')
            if session_key_elem is not None and session_key_elem.text:
                session_key = session_key_elem.text.strip()
                
                # Cache the new session key
                self._cached_session_key = session_key
                self.connection.queue_message("vvv", f"ITSI HttpApi: Successfully obtained and cached session key")
                return session_key
            else:
                self.connection.queue_message("vvv", f"ITSI HttpApi: No sessionKey found in response")
                return ""
                
        except Exception as e:
            self.connection.queue_message("vvv", f"ITSI HttpApi: Session key retrieval failed: {e}")
            return ""

    def get_headers(self, force_refresh: bool = False):
        """Get headers with authentication for Splunk ITSI API requests.
        
        Args:
            force_refresh: If True, bypass cache and refresh authentication
            
        Returns:
            dict: Headers with authentication (always returns a copy)
        """
        # Return cached headers unless force refresh
        if not force_refresh and self._cached_auth_headers:
            self.connection.queue_message("vvv", f"ITSI HttpApi: Using cached authentication headers")
            return self._cached_auth_headers.copy()
        
        headers = BASE_HEADERS.copy()
        
        # 1. Try Bearer token first (highest priority) - pre-created Splunk tokens
        try:
            token = self.get_option("token")
            if token:
                self.connection.queue_message("vvv", f"ITSI HttpApi: Using Bearer token authentication")
                headers["Authorization"] = f"Bearer {token}"
                self._auth_method = "bearer_token"
                self._cached_auth_headers = headers.copy()
                return headers.copy()
        except (KeyError, Exception) as e:
            self.connection.queue_message("vvv", f"ITSI HttpApi: Token retrieval failed: {e}")
            pass
        
        # 2. Try explicit pre-defined session key (ansible_httpapi_session_key)
        # Skip this if we're falling back due to 401 with explicit session key
        if not self._fallback_to_auto_session:
            try:
                session_key = self.connection.get_option("session_key")
                if session_key:
                    self.connection.queue_message("vvv", f"ITSI HttpApi: Using explicit session key")
                    headers["Authorization"] = f"Splunk {session_key}"
                    self._auth_method = "session_key"
                    self._cached_auth_headers = headers.copy()
                    return headers.copy()
            except (KeyError, Exception):
                pass
        
        # 3. Try to get session key automatically via /services/auth/login endpoint
        try:
            user = self.connection.get_option("remote_user")
            password = self.connection.get_option("password")
            if user and password:
                session_key = self._get_session_key(user, password, force_refresh=force_refresh)
                if session_key:
                    self.connection.queue_message("vvv", f"ITSI HttpApi: Using auto-retrieved session key")
                    headers["Authorization"] = f"Splunk {session_key}"
                    self._auth_method = "auto_session"
                    self._cached_auth_headers = headers.copy()
                    
                    # Reset fallback flag after successful auto-login
                    self._fallback_to_auto_session = False
                    
                    return headers.copy()
        except (KeyError, Exception):
            pass
        
        # 4. Final fallback: Basic auth
        try:
            user = self.connection.get_option("remote_user")
            password = self.connection.get_option("password")
            if user and password:
                self.connection.queue_message("vvv", f"ITSI HttpApi: Using Basic authentication")
                credentials = base64.b64encode(f"{user}:{password}".encode("utf-8")).decode("ascii")
                headers["Authorization"] = f"Basic {credentials}"
                self._auth_method = "basic_auth"
                self._cached_auth_headers = headers.copy()
                return headers.copy()
        except (KeyError, Exception):
            pass
        
        return headers.copy()

    # ---------- main override ----------

    def send_request(self, data, *extra_args, **message_kwargs):  # type: ignore[override]
        """HttpApiBase.send_request implementation.
        
        Note: HttpApiBase.send_request is declared to return None, but for RPC compatibility
        we need to return the response data as a string. The type: ignore comment suppresses
        the type checker warning while maintaining functional compatibility.
        """
        self.connection.queue_message("vvv", f"ITSI HttpApi: Starting send_request")
        
        # Reset retry flag at the start of each request
        self._auth_retry_attempted = False
        
        try:
            self.connection.queue_message("vvv", f"ITSI HttpApi: Extracting parameters")
            # Extract parameters
            path = data
            method = message_kwargs.get("method", "GET").upper()
            body = message_kwargs.get("body", "")
            
            self.connection.queue_message("vvv", f"ITSI HttpApi: method={method}, path={path}")
            
            self.connection.queue_message("vvv", f"ITSI HttpApi: Ensuring JSON output mode")
            # Ensure JSON output mode for GET requests
            path = self._ensure_output_mode_json(path, method)
            
            self.connection.queue_message("vvv", f"ITSI HttpApi: Getting headers")
            # Get auth headers (cached if available)
            auth_headers = self.get_headers()
            
            # Merge with any custom headers from the caller (don't cache merged headers)
            headers = {**auth_headers, **message_kwargs.get("headers", {})}
            
            self.connection.queue_message("vvv", f"ITSI HttpApi: Headers prepared, making real HTTP request")
            
            # Enhanced response is now the default - allow opt-out via kwarg for special cases
            return_enhanced = bool(message_kwargs.get("return_enhanced_response", True))
            
            # Check if caller wants whitespace stripping (default True for backward compatibility)
            strip_whitespace = bool(message_kwargs.get("strip_whitespace", True))
            
            # Make the actual HTTP request to Splunk ITSI API
            try:
                # Ensure path starts with / for proper URL formation
                if not path.startswith('/'):
                    path = '/' + path
                
                self.connection.queue_message("vvv", f"ITSI HttpApi: Calling connection.send() with path='{path}'")
                
                # Use the connection's send method to make the HTTP request
                # The connection object handles the actual HTTP transport
                response = self.connection.send(path, body, method=method, headers=headers)
                
                self.connection.queue_message("vvv", f"ITSI HttpApi: Response received, extracting status and content")
                
                # Extract status, headers, and body text
                status, headers_map, response_text = self._extract_status_headers_text(response, strip_whitespace=strip_whitespace)
                
                self.connection.queue_message("vvv", f"ITSI HttpApi: Status {status}, response length: {len(response_text)}")
                
                # Reset retry flag on successful response
                self._auth_retry_attempted = False
                
                # Return enhanced JSON envelope (default) or plain body for special cases
                if return_enhanced:
                    # Filter out potentially sensitive headers by default
                    safe_headers = {k: v for k, v in headers_map.items() 
                                  if k.lower() not in ['authorization', 'set-cookie', 'cookie']}
                    payload = {
                        "status": status,
                        "headers": safe_headers,
                        "body": response_text
                    }
                    return payload
                else:
                    # Return body string only (rare use cases)
                    return response_text
                
            except Exception as http_error:
                # Handle HTTP request errors
                error_msg = str(http_error)
                self.connection.queue_message("vvv", f"ITSI HttpApi: HTTP request failed: {error_msg}")
                
                # Extract status from exception (avoid string matching when possible)
                error_status = getattr(http_error, "code", None)
                if error_status is None:
                    error_status = 500  # default server error
                
                # Check if this is a 401 error and we should attempt refresh
                if error_status == 401 and not self._auth_retry_attempted and self._auth_method in ['session_key', 'auto_session']:
                    self.connection.queue_message("vvv", f"ITSI HttpApi: 401 detected in send_request, attempting auth refresh")
                    
                    # Mark retry attempted
                    self._auth_retry_attempted = True
                    
                    # For explicit session_key that fails, try to fallback to auto-login if possible
                    if self._auth_method == 'session_key':
                        try:
                            user = self.connection.get_option("remote_user")
                            password = self.connection.get_option("password")
                            if user and password:
                                self.connection.queue_message("vvv", f"ITSI HttpApi: Explicit session_key failed, falling back to auto-login")
                                self._fallback_to_auto_session = True
                        except (KeyError, Exception):
                            pass
                    
                    # Clear cache and get fresh headers
                    self._clear_auth_cache()
                    fresh_auth_headers = self.get_headers(force_refresh=True)
                    
                    # Merge with custom headers again for retry
                    fresh_headers = {**fresh_auth_headers, **message_kwargs.get("headers", {})}
                    
                    try:
                        self.connection.queue_message("vvv", f"ITSI HttpApi: Retrying request with refreshed auth")
                        retry_response = self.connection.send(path, body, method=method, headers=fresh_headers)
                        
                        # Extract status and content from retry response
                        retry_status, retry_headers, retry_text = self._extract_status_headers_text(retry_response, strip_whitespace=strip_whitespace)
                        
                        self.connection.queue_message("vvv", f"ITSI HttpApi: Retry successful, status {retry_status}, response length: {len(retry_text)}")
                        
                        # Reset retry flag on successful retry
                        self._auth_retry_attempted = False
                        
                        # Return enhanced response for retry if requested
                        if return_enhanced:
                            safe_headers = {k: v for k, v in retry_headers.items() 
                                          if k.lower() not in ['authorization', 'set-cookie', 'cookie']}
                            payload = {
                                "status": retry_status,
                                "headers": safe_headers,
                                "body": retry_text
                            }
                            return payload
                        else:
                            return retry_text
                        
                    except Exception as retry_error:
                        retry_status = getattr(retry_error, "code", error_status)
                        self.connection.queue_message("vvv", f"ITSI HttpApi: Retry also failed: {str(retry_error)}")
                        # Fall through to return error response with retry status
                        error_status = retry_status
                
                # Return enhanced error response or backward-compatible error
                import json
                error_body = json.dumps({
                    "error": "HTTP request failed",
                    "details": error_msg,
                    "path": path,
                    "method": method
                })
                
                if return_enhanced:
                    payload = {
                        "status": int(error_status) if error_status is not None else 500,
                        "headers": {},
                        "body": error_body
                    }
                    return payload
                else:
                    return error_body
            
        except Exception as e:
            import traceback
            error_details = traceback.format_exc()
            self.connection.queue_message("vvv", f"ITSI HttpApi: Exception caught: {str(e)}")
            self.connection.queue_message("vvv", f"ITSI HttpApi: Traceback: {error_details}")
            
            # Check if caller wanted enhanced response (in case of outer exception)
            return_enhanced = bool(message_kwargs.get("return_enhanced_response", False))
            
            # Return enhanced error response or backward-compatible error
            import json
            error_body = json.dumps({
                "error": "Internal error", 
                "details": str(e).replace('"', '\\"')
            })
            
            if return_enhanced:
                payload = {
                    "status": 500,
                    "headers": {},
                    "body": error_body
                }
                return payload
            else:
                return error_body
    
    def _handle_response(self, response_content, strip_whitespace=True):
        """Handle response content from Splunk ITSI API.
        
        Args:
            response_content: Response content from connection.send()
            strip_whitespace: If True, strip leading/trailing whitespace (default True)
        
        compatible with both core httpapi and ansible.netcommon.httpapi response formats.
        """
        self.connection.queue_message("vvv", f"ITSI HttpApi: _handle_response received type: {type(response_content)}")
        self.connection.queue_message("vvv", f"ITSI HttpApi: _handle_response content: {repr(response_content)[:200]}")
        
        # Handle different response formats in order of likelihood
        if isinstance(response_content, (str, bytes)):
            # Direct string/bytes response (most common case)
            response_text = response_content.decode('utf-8') if isinstance(response_content, bytes) else response_content
        elif isinstance(response_content, tuple) and len(response_content) == 2:
            # ansible.netcommon.httpapi returns (response, buffer)
            _, buffer = response_content
            self.connection.queue_message("vvv", f"ITSI HttpApi: buffer type: {type(buffer)}, hasattr getvalue: {hasattr(buffer, 'getvalue')}")
            
            if hasattr(buffer, 'getvalue'):
                # Try to rewind buffer first
                try:
                    buffer.seek(0)
                    self.connection.queue_message("vvv", f"ITSI HttpApi: buffer seeked to 0")
                except (AttributeError, OSError):
                    self.connection.queue_message("vvv", f"ITSI HttpApi: buffer seek failed")
                
                response_text = buffer.getvalue()  # type: ignore
                self.connection.queue_message("vvv", f"ITSI HttpApi: getvalue() returned: {type(response_text)}, len: {len(response_text) if response_text else 0}")
                
                # If getvalue() returns bytes, decode to string
                if isinstance(response_text, bytes):
                    response_text = response_text.decode('utf-8')
            elif hasattr(buffer, 'read'):
                # Try to read from buffer - may need to rewind first
                try:
                    buffer.seek(0)  # Rewind to beginning
                    self.connection.queue_message("vvv", f"ITSI HttpApi: buffer seek(0) successful")
                except (AttributeError, OSError):
                    self.connection.queue_message("vvv", f"ITSI HttpApi: buffer seek(0) failed")
                    
                response_text = buffer.read()  # type: ignore
                self.connection.queue_message("vvv", f"ITSI HttpApi: read() returned: {type(response_text)}, len: {len(response_text) if response_text else 0}")
                
                if isinstance(response_text, bytes):
                    response_text = response_text.decode('utf-8')
            elif isinstance(buffer, (str, bytes)):
                response_text = buffer.decode('utf-8') if isinstance(buffer, bytes) else buffer
            else:
                response_text = str(buffer)
        elif hasattr(response_content, 'getvalue'):
            # Core httpapi StringIO/BytesIO response
            response_text = response_content.getvalue()  # type: ignore
        elif hasattr(response_content, 'read'):
            # File-like response object
            response_text = response_content.read()  # type: ignore
        elif isinstance(response_content, (list, dict)):
            # Sometimes response might be pre-parsed - convert to JSON string
            response_text = json.dumps(response_content)
        else:
            # Fallback: convert to string
            response_text = str(response_content)
        
        # Ensure we have a string (decode bytes if necessary)
        if isinstance(response_text, bytes):
            response_text = response_text.decode('utf-8')
        
        # Apply conditional whitespace stripping - useful for Splunk JSON responses but optional for raw content
        if strip_whitespace:
            response_text = response_text.strip()
        
        self.connection.queue_message("vvv", f"ITSI HttpApi: _handle_response returning: {repr(response_text)[:200]}")
        return response_text
