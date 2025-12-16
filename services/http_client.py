"""
Centralized HTTP client with proxy support, retry logic, and error handling.
All API services should use this module for external requests.
"""
import os
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from dotenv import load_dotenv

load_dotenv()

# Proxy Configuration
# Supports HTTP_PROXY, HTTPS_PROXY, and NO_PROXY environment variables
# Example in .env:
#   HTTP_PROXY=http://proxy.company.com:8080
#   HTTPS_PROXY=http://proxy.company.com:8080
#   NO_PROXY=localhost,127.0.0.1,.local

def get_proxies():
    """
    Get proxy configuration from environment variables.

    Returns:
        dict: Proxy configuration for requests library
    """
    from urllib.parse import urlparse
    import re

    proxies = {}

    http_proxy = os.getenv('HTTP_PROXY') or os.getenv('http_proxy')
    https_proxy = os.getenv('HTTPS_PROXY') or os.getenv('https_proxy')

    if http_proxy:
        # Sanitize CRLF characters to prevent header injection
        http_proxy = re.sub(r'[\r\n\x00-\x1f]', '', http_proxy)

        # Validate proxy URL to prevent SSRF
        validated_proxy = validate_proxy_url(http_proxy)
        if validated_proxy:
            proxies['http'] = validated_proxy
            # Log safely - strip credentials from output
            safe_url = sanitize_url_for_logging(validated_proxy)
            print(f"[HTTP_CLIENT] Using HTTP proxy: {safe_url}")

    if https_proxy:
        # Sanitize CRLF characters to prevent header injection
        https_proxy = re.sub(r'[\r\n\x00-\x1f]', '', https_proxy)

        # Validate proxy URL to prevent SSRF
        validated_proxy = validate_proxy_url(https_proxy)
        if validated_proxy:
            proxies['https'] = validated_proxy
            # Log safely - strip credentials from output
            safe_url = sanitize_url_for_logging(validated_proxy)
            print(f"[HTTP_CLIENT] Using HTTPS proxy: {safe_url}")

    return proxies if proxies else None


def sanitize_url_for_logging(url):
    """
    Remove credentials from URL for safe logging.

    Args:
        url: URL that may contain credentials

    Returns:
        str: URL with credentials removed
    """
    from urllib.parse import urlparse

    try:
        parsed = urlparse(url)
        # Reconstruct URL without credentials
        safe_url = f"{parsed.scheme}://{parsed.hostname}"
        if parsed.port:
            safe_url += f":{parsed.port}"
        if parsed.path:
            safe_url += parsed.path
        return safe_url
    except Exception:
        # If parsing fails, return generic message
        return "[proxy configured]"


def validate_proxy_url(url):
    """
    Validate proxy URL to prevent SSRF and malicious protocols.

    Args:
        url: Proxy URL to validate

    Returns:
        str: Validated URL or None if invalid
    """
    from urllib.parse import urlparse
    import ipaddress

    if not url:
        return None

    try:
        parsed = urlparse(url)

        # Only allow http/https schemes
        if parsed.scheme not in ['http', 'https']:
            print(f"[HTTP_CLIENT] WARNING: Invalid proxy scheme '{parsed.scheme}' - only http/https allowed")
            return None

        # Block dangerous hostnames
        blocked_hosts = ['localhost', '127.0.0.1', '::1', '[::1]', '0.0.0.0']
        if parsed.hostname and parsed.hostname.lower() in blocked_hosts:
            print(f"[HTTP_CLIENT] WARNING: Blocked proxy host '{parsed.hostname}' - localhost not allowed")
            return None

        # Block AWS metadata endpoint
        if parsed.hostname and '169.254.169.254' in parsed.hostname:
            print(f"[HTTP_CLIENT] WARNING: Blocked proxy host '{parsed.hostname}' - metadata endpoint not allowed")
            return None

        # Block private IP ranges (optional - uncomment if needed)
        # try:
        #     ip = ipaddress.ip_address(parsed.hostname)
        #     if ip.is_private or ip.is_loopback or ip.is_link_local:
        #         print(f"[HTTP_CLIENT] WARNING: Blocked private IP address: {parsed.hostname}")
        #         return None
        # except ValueError:
        #     pass  # Not an IP address, hostname is fine

        return url
    except Exception as e:
        print(f"[HTTP_CLIENT] WARNING: Invalid proxy URL format: {e}")
        return None


def create_session_with_retries(
    max_retries=3,
    backoff_factor=0.5,
    status_forcelist=(500, 502, 503, 504, 429),
    timeout=30
):
    """
    Create a requests Session with retry logic and proxy support.

    Args:
        max_retries: Maximum number of retry attempts
        backoff_factor: Backoff factor for exponential backoff (0.5 means 0.5s, 1s, 2s, ...)
        status_forcelist: HTTP status codes to retry on
        timeout: Default timeout for requests in seconds

    Returns:
        requests.Session: Configured session with retries and proxy
    """
    session = requests.Session()

    # Configure retry strategy
    retry_strategy = Retry(
        total=max_retries,
        backoff_factor=backoff_factor,
        status_forcelist=status_forcelist,
        allowed_methods=["HEAD", "GET", "POST", "PUT", "DELETE", "OPTIONS", "TRACE"]
    )

    # Mount adapter with retry strategy
    adapter = HTTPAdapter(max_retries=retry_strategy)
    session.mount("http://", adapter)
    session.mount("https://", adapter)

    # Configure proxy
    proxies = get_proxies()
    if proxies:
        session.proxies.update(proxies)

    # Store default timeout on session
    session.timeout = timeout

    return session


def safe_get(url, headers=None, timeout=30, session=None, **kwargs):
    """
    Perform a GET request with retry logic, proxy support, and error handling.

    Args:
        url: URL to fetch
        headers: Optional headers dict
        timeout: Request timeout in seconds
        session: Optional existing session (if None, creates new one)
        **kwargs: Additional arguments to pass to requests.get()

    Returns:
        requests.Response or None if error
    """
    if session is None:
        session = create_session_with_retries(timeout=timeout)

    try:
        response = session.get(
            url,
            headers=headers,
            timeout=kwargs.get('timeout', session.timeout),
            **kwargs
        )
        response.raise_for_status()
        return response
    except requests.exceptions.Timeout:
        print(f"[HTTP_CLIENT] Timeout error fetching {url}")
        return None
    except requests.exceptions.ProxyError as e:
        print(f"[HTTP_CLIENT] Proxy error: {e}")
        return None
    except requests.exceptions.ConnectionError as e:
        print(f"[HTTP_CLIENT] Connection error: {e}")
        return None
    except requests.exceptions.HTTPError as e:
        print(f"[HTTP_CLIENT] HTTP error {e.response.status_code}: {url}")
        # Re-raise 429 (rate limit) so caller can handle it
        if e.response.status_code == 429:
            raise
        return None
    except Exception as e:
        print(f"[HTTP_CLIENT] Unexpected error fetching {url}: {e}")
        return None


def safe_post(url, json_data=None, headers=None, timeout=30, session=None, **kwargs):
    """
    Perform a POST request with retry logic, proxy support, and error handling.

    Args:
        url: URL to post to
        json_data: JSON data to send
        headers: Optional headers dict
        timeout: Request timeout in seconds
        session: Optional existing session (if None, creates new one)
        **kwargs: Additional arguments to pass to requests.post()

    Returns:
        requests.Response or None if error
    """
    if session is None:
        session = create_session_with_retries(timeout=timeout)

    try:
        response = session.post(
            url,
            json=json_data,
            headers=headers,
            timeout=kwargs.get('timeout', session.timeout),
            **kwargs
        )
        response.raise_for_status()
        return response
    except requests.exceptions.Timeout:
        print(f"[HTTP_CLIENT] Timeout error posting to {url}")
        return None
    except requests.exceptions.ProxyError as e:
        print(f"[HTTP_CLIENT] Proxy error: {e}")
        return None
    except requests.exceptions.ConnectionError as e:
        print(f"[HTTP_CLIENT] Connection error: {e}")
        return None
    except requests.exceptions.HTTPError as e:
        print(f"[HTTP_CLIENT] HTTP error {e.response.status_code}: {url}")
        # Re-raise 429 (rate limit) so caller can handle it
        if e.response.status_code == 429:
            raise
        return None
    except Exception as e:
        print(f"[HTTP_CLIENT] Unexpected error posting to {url}: {e}")
        return None


# Create a global session for reuse across the application
_global_session = None

def get_global_session():
    """
    Get or create a global session for reuse.
    This improves performance by reusing connections.

    Returns:
        requests.Session: Global session with retry and proxy support
    """
    global _global_session
    if _global_session is None:
        _global_session = create_session_with_retries()
    return _global_session
