"""
Flask Webhook Server for Cisco Catalyst Center Integration
This application receives webhooks from Catalyst Center, queries ISE for session information,
sends the data to the Deskey API for processing, and resolves issues in Catalyst Center.

Key Features:
- HTTPS webhook receiver
- ISE session information retrieval
- Deskey API integration
- Multiple session handling
- Issue resolution tracking and automation
- Duplicate webhook detection
- Comprehensive logging system
"""

from flask import Flask, request, jsonify
import json
import requests
import urllib3
import xmltodict
import time
import threading
from datetime import datetime
import os

# Disable SSL warnings for self-signed certificates
# This is needed because we're using self-signed certificates in the lab environment
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Initialize Flask application
app = Flask(__name__)

# ============================================================================
# CONFIGURATION SECTION
# ============================================================================

# Catalyst Center Configuration
DNAC_HOST = "192.168.101.2"
DNAC_USERNAME = "your_dnac_username"  # Replace with your Catalyst Center username
DNAC_PASSWORD = "your_dnac_password"  # Replace with your Catalyst Center password

# ISE (Identity Services Engine) Configuration
# These credentials are used to authenticate to ISE's Monitoring API
ISE_HOST = "192.168.101.3"
ISE_USERNAME = "your_ise_username"  # Replace with your ISE admin username
ISE_PASSWORD = "your_ise_password"  # Replace with your ISE admin password

# Deskey API Configuration
# This external API receives user and switch port information for further processing
DESKEY_API_URL = "https://deskey.optusdart.com/api/deskey/singtel/cisco/webhook"
DESKEY_API_KEY = "QIYGBFDSJKL"  # API key for authentication
DESKEY_API_SECRET = "fGHji9-2KiOPs5-DfjHGf3"  # API secret for authentication

# Logging Configuration
LOG_DIR = "logs"  # Directory to store log files
WEBHOOK_LOG = os.path.join(LOG_DIR, "webhook_received.log")
SESSION_LOG = os.path.join(LOG_DIR, "session_details.log")
RESOLUTION_LOG = os.path.join(LOG_DIR, "issue_resolution.log")
API_CALLS_LOG = os.path.join(LOG_DIR, "api_calls.log")

# ============================================================================
# LOGGING FUNCTIONS
# ============================================================================

def ensure_log_directory():
    """
    Ensure the logs directory exists
    Creates the directory if it doesn't exist
    """
    if not os.path.exists(LOG_DIR):
        os.makedirs(LOG_DIR)
        print(f"Created log directory: {LOG_DIR}")

def get_timestamp():
    """
    Get current timestamp in a readable format
    
    Returns:
        str: Formatted timestamp (YYYY-MM-DD HH:MM:SS)
    """
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def log_webhook_received(instance_id, device, assurance_details):
    """
    Log webhook receipt details to file
    
    Creates a formatted log entry with webhook information including:
    - Timestamp
    - Instance ID
    - Device IP
    - Assurance issue details
    
    Args:
        instance_id (str): Issue instance ID from Catalyst Center
        device (str): Device IP address
        assurance_details (str): Assurance issue description
    """
    try:
        with open(WEBHOOK_LOG, 'a') as f:
            f.write("=" * 100 + "\n")
            f.write(f"WEBHOOK RECEIVED\n")
            f.write("=" * 100 + "\n")
            f.write(f"Timestamp:                {get_timestamp()}\n")
            f.write(f"Instance ID:              {instance_id}\n")
            f.write(f"Device IP:                {device if device else 'N/A'}\n")
            f.write(f"Assurance Issue Details:  {assurance_details if assurance_details else 'N/A'}\n")
            f.write("=" * 100 + "\n\n")
        print(f"✓ Logged webhook to {WEBHOOK_LOG}")
    except Exception as e:
        print(f"Error logging webhook: {e}")

def log_session_details(sessions, instance_id):
    """
    Log ISE session details to file
    
    Creates formatted log entries for each session with:
    - Timestamp
    - Instance ID reference
    - Username
    - Network device name
    - NAS port ID
    - Switch port ID (combined)
    
    Args:
        sessions (list): List of session dictionaries
        instance_id (str): Issue instance ID for reference
    """
    try:
        with open(SESSION_LOG, 'a') as f:
            f.write("=" * 100 + "\n")
            f.write(f"SESSION DETAILS - Instance ID: {instance_id}\n")
            f.write("=" * 100 + "\n")
            f.write(f"Timestamp:                {get_timestamp()}\n")
            f.write(f"Total Sessions Found:     {len(sessions)}\n")
            f.write("-" * 100 + "\n")
            
            for idx, session in enumerate(sessions, 1):
                f.write(f"\nSession #{idx}:\n")
                f.write(f"  Username:               {session.get('user_name', 'N/A')}\n")
                f.write(f"  Network Device Name:    {session.get('network_device_name', 'N/A')}\n")
                f.write(f"  NAS Port ID:            {session.get('nas_port_id', 'N/A')}\n")
                f.write(f"  Switch Port ID:         {session.get('switch_port_id', 'N/A')}\n")
                f.write("-" * 100 + "\n")
            
            f.write("=" * 100 + "\n\n")
        print(f"✓ Logged {len(sessions)} session(s) to {SESSION_LOG}")
    except Exception as e:
        print(f"Error logging session details: {e}")

def log_issue_resolution(instance_id, success, response_data=None, error_message=None):
    """
    Log issue resolution attempt to file
    
    Creates a formatted log entry with resolution details:
    - Timestamp
    - Instance ID
    - Success/Failure status
    - Response data or error message
    
    Args:
        instance_id (str): Issue instance ID
        success (bool): Whether resolution was successful
        response_data (dict, optional): API response data
        error_message (str, optional): Error message if failed
    """
    try:
        with open(RESOLUTION_LOG, 'a') as f:
            f.write("=" * 100 + "\n")
            f.write(f"ISSUE RESOLUTION ATTEMPT\n")
            f.write("=" * 100 + "\n")
            f.write(f"Timestamp:                {get_timestamp()}\n")
            f.write(f"Instance ID:              {instance_id}\n")
            f.write(f"Status:                   {'SUCCESS' if success else 'FAILED'}\n")
            
            if success and response_data:
                f.write(f"Response Data:\n")
                f.write(json.dumps(response_data, indent=2))
                f.write("\n")
            elif error_message:
                f.write(f"Error Message:            {error_message}\n")
            
            f.write("=" * 100 + "\n\n")
        print(f"✓ Logged issue resolution to {RESOLUTION_LOG}")
    except Exception as e:
        print(f"Error logging issue resolution: {e}")

def log_api_call(api_name, method, url, request_data=None, response_status=None, 
                 response_data=None, error_message=None, duration=None):
    """
    Log API call details to file
    
    Creates comprehensive log entries for all external API calls with:
    - Timestamp
    - API service name (ISE, Catalyst Center, Deskey)
    - HTTP method (GET, POST, etc.)
    - URL endpoint
    - Request payload (if applicable)
    - Response status code
    - Response data
    - Error messages (if failed)
    - Call duration
    
    Args:
        api_name (str): Name of the API service (ISE, Catalyst Center, Deskey)
        method (str): HTTP method (GET, POST, etc.)
        url (str): Full API endpoint URL
        request_data (dict, optional): Request payload
        response_status (int, optional): HTTP response status code
        response_data (dict/str, optional): Response data
        error_message (str, optional): Error message if call failed
        duration (float, optional): Call duration in seconds
    """
    try:
        with open(API_CALLS_LOG, 'a') as f:
            f.write("=" * 100 + "\n")
            f.write(f"API CALL - {api_name}\n")
            f.write("=" * 100 + "\n")
            f.write(f"Timestamp:                {get_timestamp()}\n")
            f.write(f"Method:                   {method}\n")
            f.write(f"URL:                      {url}\n")
            
            if request_data:
                f.write(f"Request Data:\n")
                f.write(json.dumps(request_data, indent=2))
                f.write("\n")
            
            if response_status:
                f.write(f"Response Status:          {response_status}\n")
            
            if response_data:
                f.write(f"Response Data:\n")
                if isinstance(response_data, dict):
                    f.write(json.dumps(response_data, indent=2))
                else:
                    f.write(str(response_data))
                f.write("\n")
            
            if error_message:
                f.write(f"Error Message:            {error_message}\n")
            
            if duration:
                f.write(f"Duration:                 {duration:.2f} seconds\n")
            
            f.write(f"Status:                   {'SUCCESS' if not error_message else 'FAILED'}\n")
            f.write("=" * 100 + "\n\n")
        
        print(f"✓ Logged {api_name} API call to {API_CALLS_LOG}")
    except Exception as e:
        print(f"Error logging API call: {e}")

# ============================================================================
# TRACKING AND STATE MANAGEMENT
# ============================================================================

# Global dictionary to track processed issues
# Key: instanceId, Value: {'status': 'processing'|'completed', 'timestamp': time}
processed_issues = {}
# Lock for thread-safe access to processed_issues dictionary
issues_lock = threading.Lock()

def is_issue_processed(instance_id):
    """
    Check if an issue has already been processed or is currently being processed
    
    This prevents duplicate processing of the same issue when multiple webhooks
    are received for the same incident.
    
    Args:
        instance_id (str): The issue instance ID from Catalyst Center
        
    Returns:
        bool: True if issue is already processed/processing, False otherwise
    """
    with issues_lock:
        if instance_id in processed_issues:
            status = processed_issues[instance_id]['status']
            timestamp = processed_issues[instance_id]['timestamp']
            elapsed = time.time() - timestamp
            
            # If processing and less than 5 minutes old, consider it active
            if status == 'processing' and elapsed < 300:
                print(f"Issue {instance_id} is already being processed (started {elapsed:.0f}s ago)")
                return True
            # If completed and less than 1 hour old, skip it
            elif status == 'completed' and elapsed < 3600:
                print(f"Issue {instance_id} was already completed {elapsed:.0f}s ago")
                return True
            else:
                # Old entry, can be reprocessed
                return False
        return False

def mark_issue_processing(instance_id):
    """
    Mark an issue as currently being processed
    
    Args:
        instance_id (str): The issue instance ID
    """
    with issues_lock:
        processed_issues[instance_id] = {
            'status': 'processing',
            'timestamp': time.time()
        }
        print(f"Marked issue {instance_id} as processing")

def mark_issue_completed(instance_id):
    """
    Mark an issue as completed
    
    Args:
        instance_id (str): The issue instance ID
    """
    with issues_lock:
        if instance_id in processed_issues:
            processed_issues[instance_id]['status'] = 'completed'
            processed_issues[instance_id]['timestamp'] = time.time()
            print(f"Marked issue {instance_id} as completed")

# ============================================================================
# CATALYST CENTER API FUNCTIONS
# ============================================================================

def get_dnac_token():
    """
    Authenticate to Catalyst Center and get authentication token
    
    Catalyst Center uses token-based authentication. This function obtains
    a token that will be used for subsequent API calls.
    
    Returns:
        str: Authentication token, or None if authentication fails
        
    API Endpoint: /dna/system/api/v1/auth/token
    Authentication: HTTP Basic Auth
    """
    url = f"https://{DNAC_HOST}/dna/system/api/v1/auth/token"
    start_time = time.time()
    
    try:
        print(f"Authenticating to Catalyst Center at {DNAC_HOST}...")
        response = requests.post(
            url,
            auth=(DNAC_USERNAME, DNAC_PASSWORD),
            headers={"Content-Type": "application/json"},
            verify=False,
            timeout=30
        )
        response.raise_for_status()
        token = response.json()["Token"]
        duration = time.time() - start_time
        
        print("✓ Successfully authenticated to Catalyst Center")
        
        # Log the API call
        log_api_call(
            api_name="Catalyst Center (Authentication)",
            method="POST",
            url=url,
            response_status=response.status_code,
            response_data={"message": "Token obtained successfully"},
            duration=duration
        )
        
        return token
    except Exception as e:
        duration = time.time() - start_time
        print(f"Error getting Catalyst Center authentication token: {e}")
        
        # Log the failed API call
        log_api_call(
            api_name="Catalyst Center (Authentication)",
            method="POST",
            url=url,
            response_status=getattr(getattr(e, 'response', None), 'status_code', None),
            error_message=str(e),
            duration=duration
        )
        
        return None

def resolve_issue(instance_id, token):
    """
    Resolve an issue in Catalyst Center using the Issues API
    
    This function calls the Catalyst Center API to mark an issue as resolved.
    Reference: https://developer.cisco.com/docs/dna-center/2-3-7-9/resolve-the-given-lists-of-issues/
    
    Args:
        instance_id (str): The issue instance ID to resolve
        token (str): Authentication token for Catalyst Center
        
    Returns:
        dict: API response as JSON, or None if call fails
        
    API Details:
        - Method: POST
        - Endpoint: /dna/intent/api/v1/issue/resolve
        - Authentication: X-Auth-Token header
        - Payload: {"issueIds": [list of instance IDs]}
    """
    url = f"https://{DNAC_HOST}/dna/intent/api/v1/issue/resolve"
    
    headers = {
        "X-Auth-Token": token,
        "Content-Type": "application/json"
    }
    
    # Payload format: list of issue IDs to resolve
    payload = {
        "issueIds": [instance_id]
    }
    
    start_time = time.time()
    
    try:
        print(f"\nResolving issue in Catalyst Center...")
        print(f"Issue Instance ID: {instance_id}")
        print(f"URL: {url}")
        print(f"Payload: {json.dumps(payload, indent=2)}")
        
        response = requests.post(
            url,
            headers=headers,
            json=payload,
            verify=False,
            timeout=30
        )
        response.raise_for_status()
        duration = time.time() - start_time
        
        print(f"✓ Issue {instance_id} resolved successfully!")
        print(f"Response Status: {response.status_code}")
        print(f"Response: {response.text}")
        print("=" * 80)
        
        # Parse response
        response_data = None
        if response.text and response.text.strip():
            try:
                response_data = response.json()
            except json.JSONDecodeError:
                response_data = {"response": response.text}
        else:
            response_data = {"status": "success", "message": "Issue resolved"}
        
        # Log the API call
        log_api_call(
            api_name="Catalyst Center (Resolve Issue)",
            method="POST",
            url=url,
            request_data=payload,
            response_status=response.status_code,
            response_data=response_data,
            duration=duration
        )
        
        # Log issue resolution
        log_issue_resolution(
            instance_id=instance_id,
            success=True,
            response_data=response_data
        )
        
        return response_data
        
    except requests.exceptions.HTTPError as e:
        duration = time.time() - start_time
        error_msg = str(e)
        print(f"HTTP Error resolving issue: {e}")
        print(f"Status Code: {e.response.status_code if e.response else 'Unknown'}")
        print(f"Response: {e.response.text if e.response else 'No response'}")
        
        # Log the failed API call
        log_api_call(
            api_name="Catalyst Center (Resolve Issue)",
            method="POST",
            url=url,
            request_data=payload,
            response_status=e.response.status_code if e.response else None,
            error_message=error_msg,
            duration=duration
        )
        
        # Log failed resolution
        log_issue_resolution(
            instance_id=instance_id,
            success=False,
            error_message=error_msg
        )
        
        return {"status": "error", "message": error_msg}
    except Exception as e:
        duration = time.time() - start_time
        error_msg = str(e)
        print(f"Error resolving issue: {e}")
        
        # Log the failed API call
        log_api_call(
            api_name="Catalyst Center (Resolve Issue)",
            method="POST",
            url=url,
            request_data=payload,
            error_message=error_msg,
            duration=duration
        )
        
        # Log failed resolution
        log_issue_resolution(
            instance_id=instance_id,
            success=False,
            error_message=error_msg
        )
        
        return {"status": "error", "message": error_msg}

# ============================================================================
# ISE QUERY FUNCTIONS
# ============================================================================

def query_ise_session(device_ip):
    """
    Query ISE for session information based on device IP address
    
    This function calls the ISE Monitoring API to retrieve active sessions
    for a specific device (identified by IP address).
    
    Args:
        device_ip (str): The IP address of the device to query
        
    Returns:
        dict: Parsed XML response as a dictionary, or None if query fails
        
    ISE API Endpoint: /admin/API/mnt/Session/IPAddress/{device_ip}
    Authentication: HTTP Basic Auth
    Response Format: XML (converted to dict using xmltodict)
    """
    # Construct the ISE API URL with the device IP
    url = f"https://{ISE_HOST}/admin/API/mnt/Session/IPAddress/{device_ip}"
    
    # ISE Monitoring API requires XML content type
    headers = {
        "Accept": "application/xml",
        "Content-Type": "application/xml"
    }
    
    start_time = time.time()
    
    try:
        # Make GET request to ISE with basic authentication
        response = requests.get(
            url,
            auth=(ISE_USERNAME, ISE_PASSWORD),  # HTTP Basic Auth
            headers=headers,
            verify=False  # Ignore SSL certificate verification (lab environment)
        )
        response.raise_for_status()  # Raise exception for HTTP errors (4xx, 5xx)
        duration = time.time() - start_time
        
        # Convert XML response to dictionary for easier handling
        xml_data = response.text
        dict_data = xmltodict.parse(xml_data)  # Parse XML to Python dict
        
        # Log the API call
        log_api_call(
            api_name="ISE (Session Query)",
            method="GET",
            url=url,
            request_data={"device_ip": device_ip},
            response_status=response.status_code,
            response_data={"message": f"Session data retrieved for {device_ip}"},
            duration=duration
        )
        
        return dict_data
        
    except requests.exceptions.HTTPError as e:
        # Handle HTTP errors (authentication failures, not found, etc.)
        duration = time.time() - start_time
        error_msg = str(e)
        print(f"HTTP Error querying ISE: {e}")
        print(f"Status Code: {e.response.status_code if e.response else 'Unknown'}")
        print(f"Response: {e.response.text if e.response else 'No response'}")
        
        # Log the failed API call
        log_api_call(
            api_name="ISE (Session Query)",
            method="GET",
            url=url,
            request_data={"device_ip": device_ip},
            response_status=e.response.status_code if e.response else None,
            error_message=error_msg,
            duration=duration
        )
        
        return None
    except Exception as e:
        # Handle other errors (connection errors, parsing errors, etc.)
        duration = time.time() - start_time
        error_msg = str(e)
        print(f"Error querying ISE session: {e}")
        
        # Log the failed API call
        log_api_call(
            api_name="ISE (Session Query)",
            method="GET",
            url=url,
            request_data={"device_ip": device_ip},
            error_message=error_msg,
            duration=duration
        )
        
        return None

# ============================================================================
# DATA PROCESSING FUNCTIONS
# ============================================================================

def format_interface_name(interface_name):
    """
    Format interface name to shorten GigabitEthernet to Gi
    
    Cisco devices use long interface names like "GigabitEthernet1/0/1"
    This function converts them to the short format "Gi1/0/1" for readability
    
    Args:
        interface_name (str): Full interface name from ISE
        
    Returns:
        str: Shortened interface name
        
    Examples:
        GigabitEthernet1/0/1 -> Gi1/0/1
        GigabitEthernet2/0/24 -> Gi2/0/24
    """
    # Check if interface name is valid
    if not interface_name or interface_name == 'N/A':
        return interface_name
    
    # Replace GigabitEthernet with Gi using string replace
    # The '1' parameter ensures only the first occurrence is replaced
    if interface_name.startswith('GigabitEthernet'):
        interface_name = interface_name.replace('GigabitEthernet', 'Gi', 1)
    
    return interface_name

def extract_session_info(ise_data):
    """
    Extract nas_port_id, network_device_name, and user_name from ISE session data
    
    ISE returns session information in XML format with multiple possible structures.
    This function parses the data and extracts the relevant fields for all active sessions.
    
    Args:
        ise_data (dict): Parsed ISE XML response as a dictionary
        
    Returns:
        list: List of session dictionaries, each containing:
            - nas_port_id: The switch port interface (e.g., Gi1/0/1)
            - network_device_name: The name of the network device (switch)
            - user_name: The authenticated username
            - switch_port_id: Combined identifier (device_port format)
            
    Note: ISE can return either a single session (dict) or multiple sessions (list)
    """
    sessions = []  # Initialize empty list to store all sessions
    
    try:
        # Navigate to the session data - structure may vary based on ISE version
        # Common paths: sessionParameters or sessions
        if 'sessionParameters' in ise_data:
            session_list = ise_data['sessionParameters']
            
            # Handle single session or multiple sessions
            # ISE returns a dict for single session, list for multiple sessions
            if isinstance(session_list, dict):
                # Single session - convert to list for uniform processing
                session_list = [session_list]
            elif isinstance(session_list, list):
                # Multiple sessions - already in list format
                pass
            else:
                # Unknown format - return empty list
                return sessions
            
            # Process each session in the list
            for session in session_list:
                # Extract session fields (use 'N/A' as default if field missing)
                nas_port_id = session.get('nas_port_id', 'N/A')  # Switch port interface
                network_device_name = session.get('network_device_name', 'N/A')  # Switch name
                user_name = session.get('user_name', 'N/A')  # Authenticated user
                
                # Format the nas_port_id to shortened version (Gi1/0/1)
                formatted_nas_port_id = format_interface_name(nas_port_id)
                
                # Create merged switchPortId variable for Deskey API
                # Format: SwitchName_InterfaceName (e.g., Switch-01_Gi1/0/1)
                switch_port_id = f"{network_device_name}_{formatted_nas_port_id}"
                
                # Add session information to the list
                sessions.append({
                    'nas_port_id': formatted_nas_port_id,
                    'network_device_name': network_device_name,
                    'user_name': user_name,
                    'switch_port_id': switch_port_id
                })
        
    except Exception as e:
        # Handle any parsing errors
        print(f"Error extracting session info: {e}")
    
    return sessions

# ============================================================================
# EXTERNAL API INTEGRATION
# ============================================================================

def call_deskey_api(username, switch_port_id):
    """
    Call the Deskey API with username and switchPortId
    
    This function sends user authentication and switch port information to
    the Deskey external API for processing (e.g., provisioning, logging, etc.)
    
    Args:
        username (str): The authenticated username from ISE
        switch_port_id (str): Combined switch and port identifier (e.g., Switch-01_Gi1/0/1)
        
    Returns:
        dict: API response as JSON, or error dictionary if call fails
        
    API Details:
        - Method: POST
        - Authentication: Custom headers (x-ds-api-key, x-ds-api-secret)
        - Content-Type: application/json
        - Payload: {"username": "...", "switchPortId": "..."}
    """
    # Prepare API headers with authentication
    headers = {
        "Content-Type": "application/json",
        "x-ds-api-key": DESKEY_API_KEY,  # API key for authentication
        "x-ds-api-secret": DESKEY_API_SECRET  # API secret for authentication
    }
    
    # Prepare the JSON payload to send
    payload = {
        "username": username,  # User who authenticated
        "switchPortId": switch_port_id  # Switch and port they're connected to
    }
    
    start_time = time.time()
    
    try:
        # Log the API call details for debugging
        print(f"\nCalling Deskey API for user: {username}")
        print(f"URL: {DESKEY_API_URL}")
        print(f"Payload: {json.dumps(payload, indent=2)}")
        
        # Make POST request to Deskey API
        response = requests.post(
            DESKEY_API_URL,
            headers=headers,
            json=payload,  # Automatically converts dict to JSON
            verify=False,  # Ignore SSL certificate verification
            timeout=30  # 30 second timeout to prevent hanging
        )
        response.raise_for_status()  # Raise exception for HTTP errors
        duration = time.time() - start_time
        
        # Log successful API call
        print(f"✓ Deskey API call succeeded for {username}!")
        print(f"Response Status: {response.status_code}")
        print(f"Response Text: {response.text}")
        print("-" * 80)
        
        # Handle empty or non-JSON responses
        response_data = None
        if response.text and response.text.strip():
            try:
                # Try to parse JSON response
                response_data = response.json()
            except json.JSONDecodeError:
                # Response is not JSON - return raw text
                print("Response is not valid JSON, returning raw text")
                response_data = {"status": "success", "response": response.text}
        else:
            # Empty response - consider it successful
            response_data = {"status": "success", "message": "Empty response from API"}
        
        # Log the API call
        log_api_call(
            api_name="Deskey Service",
            method="POST",
            url=DESKEY_API_URL,
            request_data=payload,
            response_status=response.status_code,
            response_data=response_data,
            duration=duration
        )
        
        return response_data
        
    except requests.exceptions.HTTPError as e:
        # Handle HTTP errors (4xx, 5xx status codes)
        duration = time.time() - start_time
        error_msg = str(e)
        print(f"HTTP Error calling Deskey API for {username}: {e}")
        print(f"Status Code: {e.response.status_code if e.response else 'Unknown'}")
        print(f"Response: {e.response.text if e.response else 'No response'}")
        
        # Log the failed API call
        log_api_call(
            api_name="Deskey Service",
            method="POST",
            url=DESKEY_API_URL,
            request_data=payload,
            response_status=e.response.status_code if e.response else None,
            error_message=error_msg,
            duration=duration
        )
        
        return {"status": "error", "message": error_msg}
    except Exception as e:
        # Handle other errors (connection errors, timeouts, etc.)
        duration = time.time() - start_time
        error_msg = str(e)
        print(f"Error calling Deskey API for {username}: {e}")
        
        # Log the failed API call
        log_api_call(
            api_name="Deskey Service",
            method="POST",
            url=DESKEY_API_URL,
            request_data=payload,
            error_message=error_msg,
            duration=duration
        )
        
        return {"status": "error", "message": error_msg}

# ============================================================================
# WEBHOOK ENDPOINT
# ============================================================================

@app.route('/webhook', methods=['POST'])
def webhook_receiver():
    """
    Main webhook receiver endpoint for Catalyst Center
    
    This endpoint receives webhook notifications from Cisco Catalyst Center,
    processes the data, queries ISE for session information, sends the
    information to the Deskey API, and resolves the issue in Catalyst Center.
    
    Workflow:
        1. Receive webhook from Catalyst Center
        2. Extract "Assurance Issue Details", "Device", and "InstanceId"
        3. Log webhook receipt
        4. Check if issue is already being processed (duplicate prevention)
        5. Wait 30 seconds (allow time for ISE session to fully establish)
        6. Query ISE for active sessions on the device
        7. Log session details
        8. For each active session, send information to Deskey API
        9. Wait 30 seconds before resolving the issue
        10. Call Catalyst Center API to resolve the issue
        11. Return summary response
        
    Expected Webhook Format:
        {
            "details": {
                "Assurance Issue Details": "User defined issue...",
                "Device": "192.168.1.100"
            },
            "instanceId": "ABC123..."
        }
        
    Returns:
        JSON response with status and session information
    """
    # ========================================================================
    # STEP 1: Receive and validate webhook data
    # ========================================================================
    
    # Get JSON payload from Catalyst Center webhook
    data = request.get_json()
    if not data:
        # No data received or invalid JSON
        return jsonify({"error": "Invalid or missing JSON payload"}), 400

    # Print the complete webhook for debugging and auditing
    print("\n" + "=" * 80)
    print("Received webhook data (prettified):")
    print(json.dumps(data, indent=4, sort_keys=True))  # Pretty print JSON
    print("=" * 80)

    # ========================================================================
    # STEP 2: Extract required fields from webhook
    # ========================================================================
    
    # Extract the instance ID from the webhook (top level)
    instance_id = data.get('instanceId', None)
    
    if not instance_id:
        print("WARNING: No instanceId found in webhook")
        return jsonify({
            "status": "Webhook received",
            "error": "instanceId not found in webhook"
        }), 400
    
    print(f"\nInstance ID: {instance_id}")
    
    # Check if 'details' field exists in the webhook
    assurance_issue_details = None
    device = None
    
    if 'details' in data:
        details = data['details']
        
        # Extract "Assurance Issue Details" and "Device" fields
        assurance_issue_details = details.get('Assurance Issue Details', None)
        device = details.get('Device', None)  # This is the device IP address
        
        # Log the extracted information
        if assurance_issue_details:
            print(f"Assurance Issue Details: {assurance_issue_details}")
        else:
            print("Assurance Issue Details: Not found")
    
    # ========================================================================
    # STEP 3: Log webhook receipt
    # ========================================================================
    
    log_webhook_received(instance_id, device, assurance_issue_details)
    
    # ========================================================================
    # STEP 4: Check for duplicate processing
    # ========================================================================
    
    # Check if this issue is already being processed or was recently completed
    if is_issue_processed(instance_id):
        print(f"Skipping duplicate webhook for issue {instance_id}")
        return jsonify({
            "status": "Duplicate webhook ignored",
            "instanceId": instance_id,
            "message": "This issue is already being processed or was recently completed"
        }), 200
    
    # Mark this issue as being processed
    mark_issue_processing(instance_id)
    
    # ====================================================================
    # STEP 5: Process device information if present
    # ====================================================================
    
    if device:
        print(f"Device: {device}\n")
        
        # Add 30 second delay before querying ISE
        # This allows time for the ISE session to fully establish
        # after the initial connection/authentication
        print("Waiting 30 seconds before querying ISE...")
        time.sleep(30)  # 30 seconds delay
        print("Delay complete. Proceeding with ISE query.\n")
        
        # ================================================================
        # STEP 6: Query ISE for active sessions
        # ================================================================
        
        # Query ISE API with the device IP address
        print(f"Querying ISE for session information on device: {device}")
        ise_session_data = query_ise_session(device)
        
        if ise_session_data:
            # ISE query succeeded
            print("\n✓ ISE API Request Succeeded!")
            print("=" * 80)
            
            # ============================================================
            # STEP 7: Extract session information from ISE response
            # ============================================================
            
            # Extract all active sessions from ISE data
            sessions = extract_session_info(ise_session_data)
            
            if sessions:
                # Sessions found - process each one
                print(f"\nFound {len(sessions)} active session(s)")
                print("=" * 80)
                
                # Log session details
                log_session_details(sessions, instance_id)
                
                # Store all Deskey API responses for tracking
                deskey_responses = []
                
                # ========================================================
                # STEP 8: Call Deskey API for each active session
                # ========================================================
                
                # Loop through each session and make an API call
                # If 1 session exists, make 1 API call
                # If 3 sessions exist, make 3 API calls
                for idx, session in enumerate(sessions, 1):
                    # Log session details
                    print(f"\nProcessing Session {idx} of {len(sessions)}:")
                    print(f"nas_port_id: {session['nas_port_id']}")
                    print(f"network_device_name: {session['network_device_name']}")
                    print(f"user_name: {session['user_name']}")
                    print(f"switch_port_id: {session['switch_port_id']}")
                    print(f"\nUser \"{session['user_name']}\" has connected \"{session['network_device_name']}_{session['nas_port_id']}\"")
                    
                    # Call Deskey API for this specific session
                    deskey_response = call_deskey_api(
                        session['user_name'],  # Username from ISE
                        session['switch_port_id']  # Combined switch_port identifier
                    )
                    
                    # Store the session and its API response together
                    deskey_responses.append({
                        'session': session,
                        'api_response': deskey_response
                    })
                
                print("\n" + "=" * 80)
                print(f"Completed processing {len(sessions)} session(s)")
                print("=" * 80)
                
                # ========================================================
                # STEP 9: Wait before resolving the issue
                # ========================================================
                
                # Wait 30 seconds before resolving the issue in Catalyst Center
                # This ensures all processing is complete
                print("\nWaiting 30 seconds before resolving issue in Catalyst Center...")
                time.sleep(30)
                print("Delay complete. Proceeding with issue resolution.\n")
                
                # ========================================================
                # STEP 10: Resolve the issue in Catalyst Center
                # ========================================================
                
                # Get authentication token for Catalyst Center
                dnac_token = get_dnac_token()
                
                resolve_response = None
                if dnac_token:
                    # Call the resolve issue API
                    resolve_response = resolve_issue(instance_id, dnac_token)
                    
                    if resolve_response and resolve_response.get('status') != 'error':
                        # Mark issue as completed in our tracking
                        mark_issue_completed(instance_id)
                    else:
                        print(f"Failed to resolve issue {instance_id}")
                else:
                    print("Failed to authenticate to Catalyst Center, cannot resolve issue")
                
                # ========================================================
                # STEP 11: Return success response with all results
                # ========================================================
                
                # Return comprehensive response with all sessions and API results
                return jsonify({
                    "status": "Webhook processed successfully",
                    "instanceId": instance_id,
                    "assurance_issue_details": assurance_issue_details,
                    "device": device,
                    "total_sessions": len(sessions),  # Number of sessions processed
                    "sessions": sessions,  # All session details
                    "deskey_api_responses": deskey_responses,  # All API responses
                    "issue_resolved": resolve_response is not None and resolve_response.get('status') != 'error',
                    "resolve_response": resolve_response
                }), 200
                
            else:
                # No sessions found in ISE response
                print("No session information found in ISE response")
                
                # Still try to resolve the issue even without sessions
                print("\nWaiting 30 seconds before resolving issue in Catalyst Center...")
                time.sleep(30)
                
                dnac_token = get_dnac_token()
                resolve_response = None
                if dnac_token:
                    resolve_response = resolve_issue(instance_id, dnac_token)
                    if resolve_response and resolve_response.get('status') != 'error':
                        mark_issue_completed(instance_id)
                
                return jsonify({
                    "status": "Webhook received",
                    "instanceId": instance_id,
                    "assurance_issue_details": assurance_issue_details,
                    "device": device,
                    "error": "No session information found",
                    "issue_resolved": resolve_response is not None and resolve_response.get('status') != 'error',
                    "resolve_response": resolve_response
                }), 200
                
        else:
            # ISE query failed
            print("Failed to retrieve ISE session data")
            
            # Still try to resolve the issue
            print("\nWaiting 30 seconds before resolving issue in Catalyst Center...")
            time.sleep(30)
            
            dnac_token = get_dnac_token()
            resolve_response = None
            if dnac_token:
                resolve_response = resolve_issue(instance_id, dnac_token)
                if resolve_response and resolve_response.get('status') != 'error':
                    mark_issue_completed(instance_id)
            
            return jsonify({
                "status": "Webhook received",
                "instanceId": instance_id,
                "assurance_issue_details": assurance_issue_details,
                "device": device,
                "error": "Failed to retrieve ISE session data",
                "issue_resolved": resolve_response is not None and resolve_response.get('status') != 'error',
                "resolve_response": resolve_response
            }), 500
            
    else:
        # Device field not found in webhook
        print("Device: Not found\n")
        return jsonify({
            "status": "Webhook received",
            "instanceId": instance_id,
            "assurance_issue_details": assurance_issue_details,
            "error": "Device field not found"
        }), 200

# ============================================================================
# APPLICATION ENTRY POINT
# ============================================================================

if __name__ == '__main__':
    """
    Start the Flask application server
    
    Configuration:
        - Host: 0.0.0.0 (listen on all network interfaces)
        - Port: 5000 (HTTPS)
        - SSL Context: 'adhoc' (auto-generate self-signed certificate)
        
    Note: For production use, replace 'adhoc' SSL with proper certificates
    
    To run: python webhook_server.py
    Webhook URL: https://<server-ip>:5000/webhook
    """
    # Ensure log directory exists
    ensure_log_directory()
    
    print("\n" + "=" * 80)
    print("Starting Flask Webhook Server with Issue Resolution and Logging")
    print("=" * 80)
    print(f"Webhook Endpoint: https://0.0.0.0:5000/webhook")
    print(f"Catalyst Center Host: {DNAC_HOST}")
    print(f"ISE Host: {ISE_HOST}")
    print(f"Deskey API URL: {DESKEY_API_URL}")
    print(f"Log Directory: {LOG_DIR}")
    print("=" * 80)
    print("Log Files:")
    print(f"  - Webhook Received:     {WEBHOOK_LOG}")
    print(f"  - Session Details:      {SESSION_LOG}")
    print(f"  - Issue Resolution:     {RESOLUTION_LOG}")
    print(f"  - API Calls:            {API_CALLS_LOG}")
    print("=" * 80 + "\n")
    
    # Run the Flask server with HTTPS using adhoc SSL (self-signed certificate)
    # Requires pyOpenSSL to be installed: pip install pyopenssl
    app.run(host='0.0.0.0', port=5000, ssl_context='adhoc')
