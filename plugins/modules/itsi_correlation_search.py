#!/usr/bin/python
# -*- coding: utf-8 -*-

# (c) 2025 Splunk ITSI Ansible Collection maintainers
# GPL-3.0-or-later

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
---
module: itsi_correlation_search
short_description: Manage Splunk ITSI correlation searches
description:
  - Create, read, update, and delete correlation searches in Splunk IT Service Intelligence (ITSI).
  - A correlation search is a recurring search that generates a notable event when search results meet specific conditions.
  - Multi-KPI alerts are a type of correlation search.
  - Uses the ITSI Event Management Interface REST API for full CRUD operations.
  - Returns response format with status, headers, and body for comprehensive API interaction.
version_added: "1.0.0"
author:
  - "splunk.itsi maintainers"
options:
  name:
    description:
      - The name/title of the correlation search.
      - Required for create operations.
      - Used for lookup when correlation_search_id is not provided.
    type: str
    required: false
  correlation_search_id:
    description:
      - The correlation search ID/name for direct lookup.
      - Takes precedence over name parameter for read/update/delete operations.
      - For new correlation searches, this becomes the search name.
    type: str
    required: false
  state:
    description:
      - Desired state of the correlation search.
      - C(present) ensures the correlation search exists with specified configuration.
      - C(absent) ensures the correlation search is deleted.
      - C(query) retrieves correlation search information without changes.
    type: str
    choices: ['present', 'absent', 'query']
    default: 'query'
  search:
    description:
      - The SPL search query for the correlation search.
      - Required when creating new correlation searches.
    type: str
    required: false
  disabled:
    description:
      - Whether the correlation search is disabled.
      - Use C(false) to enable, C(true) to disable.
    type: bool
    required: false
  cron_schedule:
    description:
      - Cron schedule for the correlation search execution.
      - Standard cron format (e.g., "*/5 * * * *" for every 5 minutes).
    type: str
    required: false
  earliest_time:
    description:
      - Earliest time for the search window (e.g., "-15m", "-1h").
    type: str
    required: false
  latest_time:
    description:
      - Latest time for the search window (e.g., "now", "-5m").
    type: str
    required: false
  description:
    description:
      - Description of the correlation search purpose and functionality.
    type: str
    required: false
  actions:
    description:
      - Comma-separated list of actions to trigger (e.g., "itsi_event_generator").
    type: str
    required: false
  fields:
    description:
      - Comma-separated list of field names to include in response.
      - Useful for retrieving only specific fields when querying.
    type: str
    required: false
  filter_data:
    description:
      - MongoDB-style JSON filter for listing correlation searches.
      - Only applies when listing multiple items (no name or correlation_search_id specified).
    type: str
    required: false
  limit:
    description:
      - Maximum number of correlation searches to return when listing.
      - Only applies when listing multiple items.
    type: int
    required: false
  additional_fields:
    description:
      - Dictionary of additional fields to set on the correlation search.
      - Allows setting any valid correlation search field not covered by specific parameters.
    type: dict
    required: false

requirements:
  - Connection configuration requires C(ansible_connection=httpapi) and C(ansible_network_os=splunk.itsi.itsi_api_client).
  - Authentication via Bearer token, session key, or username/password as documented in the httpapi plugin.

notes:
  - This module manages ITSI correlation searches using the event_management_interface/correlation_search endpoint.
  - When creating correlation searches, the C(name) or C(correlation_search_id) and C(search) parameters are required.
  - For read operations, you can specify either C(name) or C(correlation_search_id) to fetch a specific search.
  - Without specifying a search identifier, the module lists all correlation searches.
  - Update operations modify only the specified fields, leaving other configuration unchanged.
  - The correlation search must exist before updating or deleting it.
"""

EXAMPLES = r"""
# Query all correlation searches
- name: List all correlation searches
  splunk.itsi.itsi_correlation_search:
    state: query
  register: all_searches

# Query specific correlation search by name
- name: Get correlation search by name
  splunk.itsi.itsi_correlation_search:
    name: "Service Monitoring - KPI Degraded"
    state: query
  register: specific_search

# Query correlation search by ID with field projection
- name: Get correlation search with specific fields
  splunk.itsi.itsi_correlation_search:
    correlation_search_id: "Service Monitoring - KPI Degraded"
    fields: "name,disabled,is_scheduled,cron_schedule,actions"
    state: query
  register: search_details

# Create new correlation search
- name: Create new correlation search
  splunk.itsi.itsi_correlation_search:
    name: "test-corrsearch-ansible"
    search: "index=itsi | head 1"
    description: "Test correlation search created by Ansible"
    disabled: false
    cron_schedule: "*/10 * * * *"
    earliest_time: "-15m"
    latest_time: "now"
    actions: "itsi_event_generator"
    state: present
  register: create_result

# Update existing correlation search
- name: Update correlation search schedule
  splunk.itsi.itsi_correlation_search:
    name: "test-corrsearch-ansible"
    cron_schedule: "*/5 * * * *"
    disabled: false
    state: present
  register: update_result

# Update using additional fields
- name: Update correlation search with custom fields
  splunk.itsi.itsi_correlation_search:
    correlation_search_id: "test-corrsearch-ansible"
    additional_fields:
      priority: "high"
      custom_field: "custom_value"
    state: present

# Delete correlation search
- name: Remove correlation search
  splunk.itsi.itsi_correlation_search:
    name: "test-corrsearch-ansible"
    state: absent
  register: delete_result

# List correlation searches with filtering
- name: List enabled correlation searches
  splunk.itsi.itsi_correlation_search:
    filter_data: '{"disabled": "0"}'
    limit: 10
    state: query
  register: enabled_searches

# Error handling example
- name: Create correlation search with error handling
  splunk.itsi.itsi_correlation_search:
    name: "monitoring-alert"
    search: "index=main error | stats count"
    state: present
  register: result
  failed_when: result.status not in [200, 201]

- name: Display result status
  debug:
    msg: "Operation completed with status {{ result.status }}"
"""

RETURN = r"""
status:
  description: HTTP status code from the ITSI API response
  returned: always
  type: int
  sample: 200
headers:
  description: HTTP response headers from the ITSI API
  returned: always
  type: dict
  sample:
    Content-Type: application/json
    Server: Splunkd
body:
  description: Response body from the ITSI API
  returned: always
  type: str
  sample: '{"name": "test-search", "disabled": "0"}'
correlation_searches:
  description: List of correlation searches (when listing multiple)
  returned: when state=query and no specific search is requested
  type: list
  elements: dict
  sample: [{"name": "Search 1", "disabled": "0"}, {"name": "Search 2", "disabled": "1"}]
correlation_search:
  description: Single correlation search details
  returned: when state=query and specific search is requested
  type: dict
  sample: {"name": "test-search", "disabled": "0", "search": "index=main | head 1"}
changed:
  description: Whether the correlation search was modified
  returned: always
  type: bool
  sample: true
operation:
  description: The operation that was performed
  returned: always
  type: str
  sample: "create"
"""

import json
from urllib.parse import urlencode, quote_plus

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.connection import Connection

# EMI endpoint for all correlation search operations
BASE_EVENT_MGMT = "servicesNS/nobody/SA-ITOA/event_management_interface/correlation_search"

# ---- Tiny idempotency & shape-refactor helpers ---------------------------------
COMPARE_FIELDS = [
    "search", "disabled", "cron_schedule",
    "earliest_time", "latest_time", "description", "actions",
    "dispatch.earliest_time", "dispatch.latest_time",
]

def _flatten_search_entry(entry):
    """Return Splunk saved-search `content` as a flat dict + minimal metadata."""
    content = dict(entry.get("content", {}))
    content["_meta"] = {
        "name": entry.get("name"),
        "id": entry.get("id"),
        "links": entry.get("links", {}),
        "acl": entry.get("acl", {}),
    }
    return content

def _flatten_search_object(obj):
    """
    Accept any of the known REST shapes (EAI entry envelope, already-flat dict)
    and return a flat dict of fields with `_meta`.
    """
    if isinstance(obj, dict):
        if "entry" in obj and isinstance(obj["entry"], list) and obj["entry"]:
            return _flatten_search_entry(obj["entry"][0])
        if "content" in obj and isinstance(obj["content"], dict):
            return _flatten_search_entry({
                "content": obj["content"],
                "name": obj.get("name"),
                "id": obj.get("id"),
                "links": obj.get("links", {}),
                "acl": obj.get("acl", {}),
            })
        flat = dict(obj)
        flat.setdefault("_meta", {})
        return flat
    return {"_meta": {}, "raw": obj}

def _canonicalize(payload):
    """
    Reduce an object to just the fields we compare/update. Handles both
    desired (module args) and current (Splunk GET) shapes.
    """
    if not isinstance(payload, dict):
        return {}
    # Unwrap to content if needed
    if "entry" in payload or "content" in payload:
        payload = _flatten_search_object(payload)
    # Map desired `earliest_time`/`latest_time` to `dispatch.*` family for compare
    out = {}
    src = payload
    # preferred keys from saved/searches - only include if explicitly provided
    if "dispatch.earliest_time" in src or "earliest_time" in src:
        out["dispatch.earliest_time"] = src.get("dispatch.earliest_time", src.get("earliest_time"))
    if "dispatch.latest_time" in src or "latest_time" in src:
        out["dispatch.latest_time"] = src.get("dispatch.latest_time", src.get("latest_time"))
    # passthroughs
    for k in ("search", "description", "cron_schedule", "actions"):
        if k in src:
            out[k] = src[k]
    # normalize boolean-like
    if "disabled" in src:
        v = src["disabled"]
        if isinstance(v, bool):
            out["disabled"] = "1" if v else "0"
        else:
            out["disabled"] = str(v)
    return out

def _diff_canonical(desired_canon, current_canon):
    """Return a shallow diff: {field: (current, desired)} where values differ."""
    diffs = {}
    # Only compare fields that are explicitly provided by the user
    for k in desired_canon.keys():
        dv = desired_canon.get(k)
        cv = current_canon.get(k)
        # treat None and "" as equal for time fields
        if k.startswith("dispatch.") and (dv in (None, "") and cv in (None, "")):
            continue
        if str(dv) != str(cv):
            diffs[k] = (cv, dv)
    return diffs


def _send_request(conn, method, path, params=None, payload=None, use_form_data=False):
    """
    Send request via itsi_api_client with enhanced response format.
    
    Args:
        conn: Connection object
        method: HTTP method (GET, POST, DELETE)
        path: API path
        params: Query parameters dict
        payload: Request body data
        use_form_data: If True, send payload as form data instead of JSON
        
    Returns:
        tuple: (status_code, response_dict)
    """
    method = method.upper()

    # Build query string from params
    if params:
        query_params = {k: v for k, v in params.items() if v is not None and v != ""}
        if query_params:
            sep = "&" if "?" in path else "?"
            path = f"{path}{sep}{urlencode(query_params, doseq=True)}"

    # Prepare body data and headers
    extra_headers = {}
    if use_form_data and isinstance(payload, dict):
        # For form data, URL-encode the parameters
        body = urlencode(payload, doseq=True)
        extra_headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json"
        }
    elif isinstance(payload, (dict, list)):
        body = json.dumps(payload)
    elif payload is None:
        body = ""
    else:
        body = str(payload)

    try:
        # Use response format from itsi_api_client
        result = conn.send_request(path, method=method, body=body, headers=extra_headers)
        
        # Validate response format
        if not isinstance(result, dict) or "status" not in result or "body" not in result:
            return 500, {"error": f"Invalid response format from send_request. Expected dict with 'status' and 'body', got: {type(result)}"}

        status = result["status"]
        headers = result.get("headers", {})
        body_text = result["body"]
        
        # Parse response body
        if body_text:
            try:
                parsed_data = json.loads(body_text)
                # Ensure we always return a dict, even if API returns a list
                if isinstance(parsed_data, list):
                    data = {"results": parsed_data}
                elif isinstance(parsed_data, dict):
                    data = parsed_data
                else:
                    data = {"raw_response": parsed_data}
            except ValueError:
                data = {"raw_response": body_text}
        else:
            data = {}
        
        # Include headers in response for debugging (ensure data is dict)
        if isinstance(data, dict):
            data["_response_headers"] = headers
        else:
            # This should not happen with the logic above, but just in case
            data = {"results": data, "_response_headers": headers}
        
        return status, data
            
    except Exception as e:
        error_text = str(e)
        
        # Handle common error patterns
        if "401" in error_text or "Unauthorized" in error_text:
            return 401, {"error": "Authentication failed"}
        elif "404" in error_text or "Not Found" in error_text:
            return 404, {"error": "Resource not found"}
        else:
            return 500, {"error": error_text}


def _normalize_to_list(data):
    """
    Normalize Splunk API responses to a list of correlation searches.
    
    Args:
        data: Response data from Splunk API
        
    Returns:
        list: List of correlation search objects
    """
    if isinstance(data, dict):
        # Handle Splunk REST API entry format
        if "entry" in data and isinstance(data["entry"], list):
            return data["entry"]
        if "results" in data and isinstance(data["results"], list):
            return data["results"]
        # Single object response
        return [data]
    elif isinstance(data, list):
        return data
    return []


def get_correlation_search(conn, search_identifier, fields=None):
    """EMI GET → always return flattened object on 200."""
    path = f"{BASE_EVENT_MGMT}/{quote_plus(search_identifier)}"
    params = {"output_mode": "json"}
    if fields:
        params["fields"] = ",".join(fields) if isinstance(fields, (list, tuple)) else fields
    status, data = _send_request(conn, "GET", path, params=params)
    if status == 200 and isinstance(data, dict):
        flat = _flatten_search_object(data)
        if isinstance(data, dict) and "_response_headers" in data:
            flat["_response_headers"] = data.get("_response_headers", {})
        return 200, flat
    return status, data


def list_correlation_searches(conn, fields=None, filter_data=None, limit=None):
    """
    List correlation searches with optional filtering.
    
    Args:
        conn: Connection object
        fields: Optional comma-separated field list
        filter_data: Optional MongoDB-style filter JSON string
        limit: Optional limit for number of results
        
    Returns:
        tuple: (status_code, correlation_searches_list)
    """
    params = {}
    
    # Always request JSON output format
    params["output_mode"] = "json"
    
    if fields:
        params["fields"] = ",".join(fields) if isinstance(fields, (list, tuple)) else fields
    if filter_data:
        params["filter_data"] = filter_data
    if limit:
        params["limit"] = limit
    
    # Use Event Management Interface for list operations
    status, data = _send_request(conn, "GET", BASE_EVENT_MGMT, params=params)
    
    if status == 200:
        entries = _normalize_to_list(data)
        results = [_flatten_search_object(e) for e in entries]
        result_data = {
            "correlation_searches": results,
            "_response_headers": data.get("_response_headers", {}) if isinstance(data, dict) else {}
        }
        return status, result_data
    else:
        return status, data


def create_correlation_search(conn, search_data):
    """
    Create a new correlation search via EMI.
    
    Args:
        conn: Connection object
        search_data: Dictionary containing correlation search configuration
        
    Returns:
        tuple: (status_code, response_data)
    """
    # Prepare payload for EMI creation - handle time field formats
    payload = dict(search_data)
    
    # Map dispatch.* time fields to EMI format for creation consistency
    if "dispatch.earliest_time" in payload:
        payload["earliest_time"] = payload.pop("dispatch.earliest_time")
    if "dispatch.latest_time" in payload:
        payload["latest_time"] = payload.pop("dispatch.latest_time")
    
    # Ensure both EMI and dispatch formats are present for complete creation
    if "earliest_time" in payload:
        payload["dispatch.earliest_time"] = payload["earliest_time"]
    if "latest_time" in payload:
        payload["dispatch.latest_time"] = payload["latest_time"]
    
    # Use Event Management Interface for creation with JSON output
    params = {"output_mode": "json"}
    status, data = _send_request(conn, "POST", BASE_EVENT_MGMT, params=params, payload=payload)
    return status, data


def update_correlation_search(conn, search_identifier, update_data):
    """
    Update correlation search via EMI with is_partial_data=1.
    
    Args:
        conn: Connection object
        search_identifier: Correlation search name or ID
        update_data: Dictionary containing fields to update
        
    Returns:
        tuple: (status_code, response_data)
    """
    path = f"{BASE_EVENT_MGMT}/{quote_plus(search_identifier)}"
    params = {"output_mode": "json", "is_partial_data": "1"}
    
    # Prepare JSON payload - EMI needs name in the body for some ITSI builds
    payload = {"name": search_identifier}
    
    # Add update fields to payload
    if update_data:
        # Include both EMI and dispatch time field formats
        u = dict(update_data)
        if "dispatch.earliest_time" in u:
            earliest_val = u["dispatch.earliest_time"]
            u["earliest_time"] = earliest_val  # EMI format
            # Keep dispatch format as well for consistency
        if "dispatch.latest_time" in u:
            latest_val = u["dispatch.latest_time"]
            u["latest_time"] = latest_val  # EMI format
            # Keep dispatch format as well for consistency
        payload.update(u)
    
    return _send_request(conn, "POST", path, params=params, payload=payload)


def delete_correlation_search(conn, search_identifier):
    """
    Delete a correlation search.
    
    Args:
        conn: Connection object
        search_identifier: Correlation search name or ID
        
    Returns:
        tuple: (status_code, response_data)
    """
    # Use Event Management Interface for delete operations with JSON output
    path = f"{BASE_EVENT_MGMT}/{quote_plus(search_identifier)}"
    params = {"output_mode": "json"}
    status, data = _send_request(conn, "DELETE", path, params=params)
    return status, data


def ensure_present(conn, search_identifier, desired_data, result):
    """
    Idempotent ensure-present:
    1) Check via EMI API for current state
    2) If present: compare canonical shapes; update only if needed  
    3) If absent: create via EMI, then GET to return uniform shape
    """
    # Use EMI API consistently for all operations
    current_status, current_obj = get_correlation_search(conn, search_identifier)
    if current_status == 200:
        # Object exists - compare current state with desired state
        existing_flat = _flatten_search_object(current_obj) if isinstance(current_obj, dict) else {}
        current_c = _canonicalize(existing_flat)
        desired_c = _canonicalize(desired_data)
        
        # Merge desired changes with current state to get complete desired state
        complete_desired = dict(current_c)  # Start with current state
        complete_desired.update(desired_c)   # Apply only the fields that were explicitly provided
        
        diff = _diff_canonical(complete_desired, current_c)
        if not diff:
            result.update({"changed": False, "status": 200, "operation": "no_change",
                           "headers": current_obj.get("_response_headers", {}) if isinstance(current_obj, dict) else {},
                           "body": json.dumps({"existing": current_c, "desired": complete_desired, "diff": {}})})
            return
        # Update only what changed
        # Handle is_scheduled logic: only set when cron_schedule changed and not already scheduled
        update_payload = dict(desired_c)
        cron_changed = "cron_schedule" in diff
        if cron_changed:
            current_is_scheduled = str(existing_flat.get("is_scheduled", "0")).lower() in ("1", "true")
            if not current_is_scheduled:
                update_payload["is_scheduled"] = "1"
        
        upd_status, upd_body = update_correlation_search(conn, search_identifier, update_payload)
        result.update({"changed": (upd_status == 200), "status": upd_status, "operation": "update",
                       "headers": upd_body.get("_response_headers", {}) if isinstance(upd_body, dict) else {},
                       "body": json.dumps({"existing": current_c, "desired": desired_c, "diff": diff})})
        return
    elif current_status == 404:
        # Object doesn't exist - create new correlation search
        create_status, create_body = create_correlation_search(conn, desired_data)
                        
        # normalize post-create by reading back via EMI API for consistency
        after_status, after_obj = get_correlation_search(conn, search_identifier)
        normalized = _flatten_search_object(after_obj) if after_status == 200 else {}
        result.update({"changed": (create_status == 200), "status": create_status, "operation": "create",
                       "headers": create_body.get("_response_headers", {}) if isinstance(create_body, dict) else {},
                       "body": json.dumps(normalized)})
        return
    else:
        # bubble up unexpected error from EMI API
        result.update({"changed": False, "status": current_status, "operation": "error",
                       "body": json.dumps(current_obj) if isinstance(current_obj, dict) else str(current_obj)})
        return


def main():
    """Main module execution."""
    # Define module arguments
    module_args = dict(
        name=dict(type='str', required=False),
        correlation_search_id=dict(type='str', required=False),
        state=dict(type='str', choices=['present', 'absent', 'query'], default='query'),
        search=dict(type='str', required=False),
        disabled=dict(type='bool', required=False),
        cron_schedule=dict(type='str', required=False),
        earliest_time=dict(type='str', required=False),
        latest_time=dict(type='str', required=False),
        description=dict(type='str', required=False),
        actions=dict(type='str', required=False),
        fields=dict(type='str', required=False),
        filter_data=dict(type='str', required=False),
        limit=dict(type='int', required=False),
        additional_fields=dict(type='dict', required=False),
    )

    # Create AnsibleModule instance
    module = AnsibleModule(
        argument_spec=module_args,
        supports_check_mode=True
    )

    # Check for httpapi connection
    if not getattr(module, "_socket_path", None):
        module.fail_json(msg="Use ansible_connection=httpapi and ansible_network_os=splunk.itsi.itsi_api_client")

    try:
        # Get connection to httpapi plugin
        conn = Connection(module._socket_path)
        
        # Extract parameters
        name = module.params.get('name')
        correlation_search_id = module.params.get('correlation_search_id')
        state = module.params['state']
        search_query = module.params.get('search')
        disabled = module.params.get('disabled')
        cron_schedule = module.params.get('cron_schedule')
        earliest_time = module.params.get('earliest_time')
        latest_time = module.params.get('latest_time')
        description = module.params.get('description')
        actions = module.params.get('actions')
        fields = module.params.get('fields')
        filter_data = module.params.get('filter_data')
        limit = module.params.get('limit')
        additional_fields = module.params.get('additional_fields', {})

        # Determine search identifier (correlation_search_id takes precedence)
        search_identifier = correlation_search_id or name

        # Initialize result structure
        result = {
            'changed': False,
            'status': 0,
            'headers': {},
            'body': '',
            'operation': 'none'
        }

        # Handle different states
        if state == 'query':
            if search_identifier:
                # Query specific correlation search via EMI API
                status, data = get_correlation_search(conn, search_identifier, fields)
                result.update({
                    'status': status,
                    'headers': data.get('_response_headers', {}),
                    'body': json.dumps(data) if isinstance(data, (dict, list)) else str(data),
                    'operation': 'query'
                })
                
                if status == 200:
                    result['correlation_search'] = data
                elif status == 404:
                    result['correlation_search'] = None
                    
            else:
                # List all correlation searches
                status, data = list_correlation_searches(conn, fields, filter_data, limit)
                # Ensure data is a dict for safe access
                if not isinstance(data, dict):
                    data = {"results": data, "_response_headers": {}}
                
                result.update({
                    'status': status,
                    'headers': data.get('_response_headers', {}),
                    'body': json.dumps(data) if isinstance(data, (dict, list)) else str(data),
                    'operation': 'list',
                    'correlation_searches': data.get('correlation_searches', [])
                })

        elif state == 'present':
            if not search_identifier:
                module.fail_json(msg="Either 'name' or 'correlation_search_id' is required for present state")
            
            # Only require search when we will create - check if object exists first via EMI
            current_status, current_data = get_correlation_search(conn, search_identifier)
            if current_status != 200 and not search_query:
                module.fail_json(msg="'search' parameter is required when creating new correlation search")
            
            # Build desired data
            desired_data = {
                'name': search_identifier
            }
            
            # Only include search if provided (required for create, optional for update)
            if search_query:
                desired_data['search'] = search_query
            
            # Add optional fields
            if disabled is not None:
                desired_data['disabled'] = disabled
            if cron_schedule:
                desired_data['cron_schedule'] = cron_schedule
            if earliest_time:
                desired_data['earliest_time'] = earliest_time
            if latest_time:
                desired_data['latest_time'] = latest_time
            if description:
                desired_data['description'] = description
            if actions:
                desired_data['actions'] = actions
            
            # Add additional fields
            if additional_fields:
                desired_data.update(additional_fields)
            
            if module.check_mode:
                # Determine if this would be a create or update operation
                existing_status, existing_data = get_correlation_search(conn, search_identifier)
                if existing_status == 200:
                    # Would be an update operation
                    operation = 'update'
                else:
                    # Would be a create operation
                    operation = 'create'
                
                result.update({
                    'changed': True,
                    'status': 200,
                    'operation': operation,
                    'body': json.dumps(desired_data)
                })
            else:
                ensure_present(conn, search_identifier, desired_data, result)

        elif state == 'absent':
            if not search_identifier:
                module.fail_json(msg="Either 'name' or 'correlation_search_id' is required for absent state")
            
            # Check if correlation search exists via EMI
            existing_status, existing_data = get_correlation_search(conn, search_identifier)
            
            if existing_status == 200:
                # Delete correlation search
                if module.check_mode:
                    result.update({
                        'changed': True,
                        'status': 204,
                        'operation': 'delete',
                        'body': ''
                    })
                else:
                    status, data = delete_correlation_search(conn, search_identifier)
                    result.update({
                        'changed': status == 204,
                        'status': 204,
                        'headers': data.get('_response_headers', {}),
                        'body': json.dumps(data) if isinstance(data, (dict, list)) else str(data),
                        'operation': 'delete'
                    })
            else:
                # Already doesn't exist
                result.update({
                    'changed': False,
                    'status': 404,
                    'operation': 'no_change',
                    'body': 'Correlation search already absent'
                })

        # Return results
        module.exit_json(**result)

    except Exception as e:
        module.fail_json(
            msg=f"Exception occurred: {str(e)}",
            name=module.params.get('name'),
            correlation_search_id=module.params.get('correlation_search_id'),
            state=module.params.get('state')
        )


if __name__ == '__main__':
    main()