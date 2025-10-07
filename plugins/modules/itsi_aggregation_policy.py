#!/usr/bin/python
# -*- coding: utf-8 -*-

# (c) 2025 Splunk ITSI Ansible Collection maintainers
# GPL-3.0-or-later

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
---
module: itsi_aggregation_policy
short_description: Manage Splunk ITSI aggregation policies
description:
  - Create, read, update, and delete aggregation policies in Splunk IT Service Intelligence (ITSI).
  - An aggregation policy determines how notable events are grouped together into episodes.
  - Uses the ITSI Event Management Interface REST API for full CRUD operations.
  - Returns response format with status, headers, and body for comprehensive API interaction.
version_added: "1.0.0"
author:
  - "splunk.itsi maintainers"
options:
  title:
    description:
      - The title/name of the aggregation policy.
      - Required for create operations.
      - Used for lookup when policy_id is not provided.
    type: str
    required: false
  policy_id:
    description:
      - The aggregation policy ID/key for direct lookup.
      - Takes precedence over title parameter for read/update/delete operations.
      - For new policies, this becomes the policy identifier.
    type: str
    required: false
  state:
    description:
      - Desired state of the aggregation policy.
      - C(present) ensures the aggregation policy exists with specified configuration.
      - C(absent) ensures the aggregation policy is deleted.
      - C(query) retrieves aggregation policy information without changes.
    type: str
    choices: ['present', 'absent', 'query']
    default: 'query'
  description:
    description:
      - Description of the aggregation policy purpose and functionality.
    type: str
    required: false
  disabled:
    description:
      - Whether the aggregation policy is disabled.
      - Use C(false) to enable, C(true) to disable.
    type: bool
    required: false
  filter_criteria:
    description:
      - Filter criteria that determines which notable events this policy applies to.
      - Dictionary with 'condition' (AND/OR) and 'items' array.
    type: dict
    required: false
  breaking_criteria:
    description:
      - Breaking criteria that determines when to create a new episode.
      - Dictionary with 'condition' (AND/OR) and 'items' array.
    type: dict
    required: false
  group_severity:
    description:
      - Default severity level for episodes created by this policy.
      - Common values are 'info', 'low', 'medium', 'high', 'critical'.
    type: str
    required: false
  group_status:
    description:
      - Default status for episodes created by this policy.
      - Common values are 'new', 'in_progress', 'pending', 'resolved', 'closed'.
    type: str
    required: false
  group_assignee:
    description:
      - Default assignee for episodes created by this policy.
    type: str
    required: false
  group_title:
    description:
      - Template for episode titles created by this policy.
      - Can use field substitution like '%title%', '%description%'.
    type: str
    required: false
  group_description:
    description:
      - Template for episode descriptions created by this policy.
      - Can use field substitution like '%title%', '%description%'.
    type: str
    required: false
  split_by_field:
    description:
      - Field to split episodes by (creates separate episodes per unique value).
    type: str
    required: false
  priority:
    description:
      - Priority level of the aggregation policy (1-10).
    type: int
    required: false
  rules:
    description:
      - List of action rules to execute when episodes are created.
      - Each rule is a dictionary with activation criteria and actions.
    type: list
    elements: dict
    required: false
  fields:
    description:
      - Comma-separated list of field names to include in response.
      - Useful for retrieving only specific fields when querying.
    type: str
    required: false
  filter_data:
    description:
      - MongoDB-style JSON filter for listing aggregation policies.
      - Only applies when listing multiple items (no title or policy_id specified).
    type: str
    required: false
  limit:
    description:
      - Maximum number of aggregation policies to return when listing.
      - Only applies when listing multiple items.
    type: int
    required: false
  additional_fields:
    description:
      - Dictionary of additional fields to set on the aggregation policy.
      - Allows setting any valid policy field not covered by specific parameters.
    type: dict
    required: false

requirements:
  - Connection configuration requires C(ansible_connection=httpapi) and C(ansible_network_os=splunk.itsi.itsi_api_client).
  - Authentication via Bearer token, session key, or username/password as documented in the httpapi plugin.

notes:
  - This module manages ITSI aggregation policies using the event_management_interface/notable_event_aggregation_policy endpoint.
  - When creating or updating policies, either C(title) or C(policy_id) parameter is required.
  - For read operations, you can specify either C(title) or C(policy_id) to fetch a specific policy.
  - Without specifying a policy identifier, the module lists all aggregation policies.
  - Update operations modify only the specified fields, leaving other configuration unchanged.
  - The aggregation policy must exist before updating or deleting it.
"""

EXAMPLES = r"""
# Query all aggregation policies
- name: List all aggregation policies
  splunk.itsi.itsi_aggregation_policy:
    state: query
  register: all_policies

# Query specific aggregation policy by title
- name: Get aggregation policy by title
  splunk.itsi.itsi_aggregation_policy:
    title: "Default Policy"
    state: query
  register: specific_policy

# Query aggregation policy by ID with field projection
- name: Get aggregation policy with specific fields
  splunk.itsi.itsi_aggregation_policy:
    policy_id: "itsi_default_policy"
    fields: "title,disabled,priority,group_severity"
    state: query
  register: policy_details

# Create new aggregation policy
- name: Create new aggregation policy
  splunk.itsi.itsi_aggregation_policy:
    title: "Test Aggregation Policy (Ansible)"
    description: "Test policy created by Ansible"
    disabled: false
    priority: 5
    group_severity: "medium"
    group_status: "new"
    group_title: "%title%"
    group_description: "%description%"
    filter_criteria:
      condition: "AND"
      items: []
    breaking_criteria:
      condition: "AND"
      items: []
    state: present
  register: create_result

# Update existing aggregation policy
- name: Update aggregation policy settings
  splunk.itsi.itsi_aggregation_policy:
    title: "Test Aggregation Policy (Ansible)"
    group_severity: "high"
    disabled: false
    state: present
  register: update_result

# Update using additional fields
- name: Update aggregation policy with custom fields
  splunk.itsi.itsi_aggregation_policy:
    policy_id: "test_policy_key"
    additional_fields:
      split_by_field: "source"
      sub_group_limit: "100"
    state: present

# Delete aggregation policy
- name: Remove aggregation policy
  splunk.itsi.itsi_aggregation_policy:
    title: "Test Aggregation Policy (Ansible)"
    state: absent
  register: delete_result

# List aggregation policies with filtering
- name: List enabled aggregation policies
  splunk.itsi.itsi_aggregation_policy:
    filter_data: '{"disabled": 0}'
    limit: 10
    state: query
  register: enabled_policies

# Error handling example
- name: Create aggregation policy with error handling
  splunk.itsi.itsi_aggregation_policy:
    title: "Critical Service Alert Policy"
    description: "Groups critical service alerts"
    group_severity: "critical"
    state: present
  register: result
  failed_when: result.status >= 400 and result.status != 409
"""

RETURN = r"""
changed:
  description: Whether the aggregation policy was modified
  type: bool
  returned: always
  sample: true
status:
  description: HTTP status code from the API response
  type: int
  returned: always
  sample: 200
headers:
  description: HTTP response headers from the API
  type: dict
  returned: always
  sample: {"content-type": "application/json"}
body:
  description: Raw response body from the API
  type: str
  returned: always
  sample: '{"_key": "policy123"}'
operation:
  description: The operation performed (create, update, delete, query, list, no_change)
  type: str
  returned: always
  sample: "create"
aggregation_policy:
  description: The aggregation policy data (single policy query)
  type: dict
  returned: when state=query and single policy queried
  sample:
    title: "Default Policy"
    description: "Default aggregation policy"
    disabled: 0
    _key: "itsi_default_policy"
aggregation_policies:
  description: List of aggregation policies (list query)
  type: list
  returned: when state=query and listing policies
  sample:
    - title: "Policy 1"
      _key: "policy1"
    - title: "Policy 2"
      _key: "policy2"
diff:
  description: Differences between current and desired state (update operations)
  type: dict
  returned: when operation=update and changes detected
  sample:
    group_severity: ["medium", "high"]
    disabled: ["1", "0"]
"""

# Standard library imports
import json
from urllib.parse import urlencode, quote_plus

# Ansible imports
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.connection import Connection


# API endpoint for Event Management Interface (EMI) aggregation policies
BASE_EVENT_MGMT = "servicesNS/nobody/SA-ITOA/event_management_interface/notable_event_aggregation_policy"


def _normalize_to_list(data):
    """Normalize various API response formats to a list."""
    if isinstance(data, list):
        return data
    elif isinstance(data, dict):
        if "entry" in data:
            entries = data["entry"]
            return entries if isinstance(entries, list) else [entries]
        else:
            return [data]
    else:
        return []


def _flatten_policy_object(policy_obj):
    """
    Flatten aggregation policy object from Splunk API response.
    Handles nested entry/content structures.
    """
    if not isinstance(policy_obj, dict):
        return policy_obj
    
    # If this is an entry object with content, extract the content
    if "entry" in policy_obj and len(policy_obj) == 1:
        return _flatten_policy_object(policy_obj["entry"])
    elif "content" in policy_obj:
        content = policy_obj["content"]
        # Merge entry-level fields with content
        result = dict(content)
        for k, v in policy_obj.items():
            if k != "content":
                result[k] = v
        return result
    else:
        return policy_obj


def _canonicalize_policy(payload):
    """
    Reduce an object to just the fields we compare/update. Handles both
    desired (module args) and current (Splunk GET) shapes.
    """
    if not isinstance(payload, dict):
        return {}
    
    # Unwrap to content if needed
    if "entry" in payload or "content" in payload:
        payload = _flatten_policy_object(payload)
    
    out = {}
    src = payload
    
    # Core fields that can be compared/updated
    for k in ("title", "description", "priority", "split_by_field", 
              "group_severity", "group_status", "group_assignee", 
              "group_title", "group_description"):
        if k in src:
            out[k] = src[k]
    
    # Complex fields that need special handling
    if "filter_criteria" in src:
        out["filter_criteria"] = src["filter_criteria"]
    if "breaking_criteria" in src:
        out["breaking_criteria"] = src["breaking_criteria"]
    if "rules" in src:
        out["rules"] = src["rules"]
    
    # Normalize boolean-like disabled field
    if "disabled" in src:
        v = src["disabled"]
        if isinstance(v, bool):
            out["disabled"] = 1 if v else 0
        else:
            out["disabled"] = int(v) if str(v).isdigit() else (1 if str(v).lower() in ('true', '1', 'yes') else 0)
    
    return out


def _diff_canonical(desired_canon, current_canon):
    """Return a shallow diff: {field: (current, desired)} where values differ."""
    diffs = {}
    # Only compare fields that are explicitly provided by the user
    for k in desired_canon.keys():
        dv = desired_canon.get(k)
        cv = current_canon.get(k)
        
        # Special handling for complex objects
        if k in ("filter_criteria", "breaking_criteria", "rules"):
            if json.dumps(dv, sort_keys=True) != json.dumps(cv, sort_keys=True):
                diffs[k] = (cv, dv)
        elif str(dv) != str(cv):
            diffs[k] = (cv, dv)
    
    return diffs


def _send_request(conn, method, path, params=None, payload=None):
    """
    Send request via itsi_api_client.
    
    Args:
        conn: Connection object
        method: HTTP method (GET, POST, DELETE)
        path: API path
        params: Query parameters dict
        payload: Request body data
        
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

    # Prepare body data
    if isinstance(payload, (dict, list)):
        body = json.dumps(payload)
    elif payload is None:
        body = ""
    else:
        body = str(payload)

    try:
        # Use response format from itsi_api_client
        result = conn.send_request(path, method=method, body=body)
        
        # Validate response format
        if not isinstance(result, dict) or "status" not in result or "body" not in result:
            return 500, {"error": f"Invalid response format from send_request. Expected dict with 'status' and 'body', got: {type(result)}"}

        status = result["status"]
        body_text = result["body"]
        
        # Parse response body
        if body_text:
            try:
                parsed_data = json.loads(body_text)
                # Add response headers to data for caller access
                if isinstance(parsed_data, dict):
                    parsed_data["_response_headers"] = result.get("headers", {})
                return status, parsed_data
            except json.JSONDecodeError:
                return status, {"raw_response": body_text, "_response_headers": result.get("headers", {})}
        else:
            return status, {"_response_headers": result.get("headers", {})}
            
    except Exception as e:
        return 500, {"error": f"Request failed: {str(e)}"}


def get_aggregation_policy(conn, policy_identifier, fields=None):
    """
    Get a specific aggregation policy by title or ID via EMI.
    
    Args:
        conn: Connection object
        policy_identifier: Policy title or ID
        fields: Comma-separated list of fields to retrieve
        
    Returns:
        tuple: (status_code, policy_data)
    """
    path = f"{BASE_EVENT_MGMT}/{quote_plus(policy_identifier)}"
    params = {"output_mode": "json"}
    
    if fields:
        params["fields"] = fields
    
    status, data = _send_request(conn, "GET", path, params=params)
    
    if status == 200:
        # Flatten the policy object for consistent access
        policy_data = _flatten_policy_object(data)
        return status, policy_data
    
    return status, data


def list_aggregation_policies(conn, fields=None, filter_data=None, limit=None):
    """
    List aggregation policies via EMI.
    
    Args:
        conn: Connection object
        fields: Comma-separated list of fields to retrieve
        filter_data: MongoDB-style JSON filter string
        limit: Maximum number of results
        
    Returns:
        tuple: (status_code, policies_data)
    """
    params = {"output_mode": "json"}
    
    if fields:
        params["fields"] = fields
    if filter_data:
        params["filter_data"] = filter_data
    if limit:
        params["limit"] = limit
    
    status, data = _send_request(conn, "GET", BASE_EVENT_MGMT, params=params)
    
    if status == 200:
        entries = _normalize_to_list(data)
        results = [_flatten_policy_object(e) for e in entries]
        result_data = {
            "aggregation_policies": results,
            "_response_headers": data.get("_response_headers", {}) if isinstance(data, dict) else {}
        }
        return status, result_data
    else:
        return status, data


def create_aggregation_policy(conn, policy_data):
    """
    Create a new aggregation policy via EMI.
    
    Args:
        conn: Connection object
        policy_data: Dictionary containing policy configuration
        
    Returns:
        tuple: (status_code, response_data)
    """
    # Ensure required fields are present with defaults
    payload = {
        "title": policy_data.get("title", "Unnamed Policy"),
        "filter_criteria": policy_data.get("filter_criteria", {"condition": "AND", "items": []}),
        "breaking_criteria": policy_data.get("breaking_criteria", {"condition": "AND", "items": []}),
        "group_severity": policy_data.get("group_severity", "normal"),
        "rules": policy_data.get("rules", [])
    }
    
    # Add any additional fields from policy_data
    for key, value in policy_data.items():
        if key not in payload:
            payload[key] = value
    
    params = {"output_mode": "json"}
    status, data = _send_request(conn, "POST", BASE_EVENT_MGMT, params=params, payload=payload)
    return status, data


def update_aggregation_policy(conn, policy_identifier, update_data):
    """
    Update aggregation policy via EMI with is_partial_data=1.
    
    Args:
        conn: Connection object
        policy_identifier: Policy title or ID
        update_data: Dictionary containing fields to update
        
    Returns:
        tuple: (status_code, response_data)
    """
    # First get current policy to ensure all required fields are present
    current_status, current_data = get_aggregation_policy(conn, policy_identifier)
    if current_status != 200:
        return current_status, current_data
    
    path = f"{BASE_EVENT_MGMT}/{quote_plus(policy_identifier)}"
    params = {"output_mode": "json", "is_partial_data": "1"}
    
    # Build payload with required fields - EMI requires these even for partial updates
    payload = {
        "title": update_data.get("title", current_data.get("title")),
        "filter_criteria": update_data.get("filter_criteria", current_data.get("filter_criteria", {"condition": "AND", "items": []})),
        "breaking_criteria": update_data.get("breaking_criteria", current_data.get("breaking_criteria", {"condition": "AND", "items": []})),
        "group_severity": update_data.get("group_severity", current_data.get("group_severity", "normal")),
        "rules": update_data.get("rules", current_data.get("rules", []))
    }
    
    # Add any additional fields from update_data
    for key, value in update_data.items():
        if key not in payload:
            payload[key] = value
    
    return _send_request(conn, "POST", path, params=params, payload=payload)


def delete_aggregation_policy(conn, policy_identifier):
    """
    Delete an aggregation policy.
    
    Args:
        conn: Connection object
        policy_identifier: Policy title or ID
        
    Returns:
        tuple: (status_code, response_data)
    """
    path = f"{BASE_EVENT_MGMT}/{quote_plus(policy_identifier)}"
    params = {"output_mode": "json"}
    status, data = _send_request(conn, "DELETE", path, params=params)
    return status, data


def ensure_present(conn, policy_identifier, desired_data, result):
    """
    Ensure aggregation policy exists and is configured as desired.
    
    Args:
        conn: Connection object
        policy_identifier: Policy title or ID
        desired_data: Desired policy configuration
        result: Result dictionary to update
    """
    # Check if policy exists
    current_status, current_data = get_aggregation_policy(conn, policy_identifier)
    
    if current_status == 200:
        # Policy exists - check if update is needed
        current_canon = _canonicalize_policy(current_data)
        desired_canon = _canonicalize_policy(desired_data)
        diff = _diff_canonical(desired_canon, current_canon)
        
        if diff:
            # Update needed
            status, data = update_aggregation_policy(conn, policy_identifier, desired_canon)
            result.update({
                'changed': True,
                'status': status,
                'headers': data.get('_response_headers', {}),
                'body': json.dumps(data) if isinstance(data, (dict, list)) else str(data),
                'operation': 'update',
                'diff': diff
            })
            
            if status == 200:
                result['aggregation_policy'] = data
        else:
            # No update needed
            result.update({
                'changed': False,
                'status': current_status,
                'headers': current_data.get('_response_headers', {}),
                'body': json.dumps(current_data) if isinstance(current_data, (dict, list)) else str(current_data),
                'operation': 'no_change',
                'aggregation_policy': current_data
            })
    
    elif current_status == 404:
        # Policy doesn't exist - create it
        status, data = create_aggregation_policy(conn, desired_data)
        result.update({
            'changed': True,
            'status': status,
            'headers': data.get('_response_headers', {}),
            'body': json.dumps(data) if isinstance(data, (dict, list)) else str(data),
            'operation': 'create'
        })
        
        if status == 200:
            result['aggregation_policy'] = data
    
    else:
        # Error retrieving policy
        result.update({
            'changed': False,
            'status': current_status,
            'headers': current_data.get('_response_headers', {}),
            'body': json.dumps(current_data) if isinstance(current_data, (dict, list)) else str(current_data),
            'operation': 'error'
        })


def main():
    """Main module function."""
    
    # Define module arguments
    module_args = dict(
        title=dict(type='str', required=False),
        policy_id=dict(type='str', required=False),
        state=dict(type='str', choices=['present', 'absent', 'query'], default='query'),
        description=dict(type='str', required=False),
        disabled=dict(type='bool', required=False),
        filter_criteria=dict(type='dict', required=False),
        breaking_criteria=dict(type='dict', required=False),
        group_severity=dict(type='str', required=False),
        group_status=dict(type='str', required=False),
        group_assignee=dict(type='str', required=False),
        group_title=dict(type='str', required=False),
        group_description=dict(type='str', required=False),
        split_by_field=dict(type='str', required=False),
        priority=dict(type='int', required=False),
        rules=dict(type='list', elements='dict', required=False),
        fields=dict(type='str', required=False),
        filter_data=dict(type='str', required=False),
        limit=dict(type='int', required=False),
        additional_fields=dict(type='dict', required=False, default={})
    )

    # Initialize module
    module = AnsibleModule(
        argument_spec=module_args,
        supports_check_mode=True
    )

    try:
        # Get connection
        conn = Connection(module._socket_path)

        # Extract parameters
        title = module.params.get('title')
        policy_id = module.params.get('policy_id')
        state = module.params['state']
        description = module.params.get('description')
        disabled = module.params.get('disabled')
        filter_criteria = module.params.get('filter_criteria')
        breaking_criteria = module.params.get('breaking_criteria')
        group_severity = module.params.get('group_severity')
        group_status = module.params.get('group_status')
        group_assignee = module.params.get('group_assignee')
        group_title = module.params.get('group_title')
        group_description = module.params.get('group_description')
        split_by_field = module.params.get('split_by_field')
        priority = module.params.get('priority')
        rules = module.params.get('rules')
        fields = module.params.get('fields')
        filter_data = module.params.get('filter_data')
        limit = module.params.get('limit')
        additional_fields = module.params.get('additional_fields', {})

        # Determine policy identifier (policy_id takes precedence)
        policy_identifier = policy_id or title

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
            if policy_identifier:
                # Query specific aggregation policy via EMI API
                status, data = get_aggregation_policy(conn, policy_identifier, fields)
                result.update({
                    'status': status,
                    'headers': data.get('_response_headers', {}),
                    'body': json.dumps(data) if isinstance(data, (dict, list)) else str(data),
                    'operation': 'query'
                })
                
                if status == 200:
                    result['aggregation_policy'] = data
                elif status == 404:
                    result['aggregation_policy'] = None
                    
            else:
                # List all aggregation policies
                status, data = list_aggregation_policies(conn, fields, filter_data, limit)
                # Ensure data is a dict for safe access
                if not isinstance(data, dict):
                    data = {"results": data, "_response_headers": {}}
                
                result.update({
                    'status': status,
                    'headers': data.get('_response_headers', {}),
                    'body': json.dumps(data) if isinstance(data, (dict, list)) else str(data),
                    'operation': 'list',
                    'aggregation_policies': data.get('aggregation_policies', [])
                })

        elif state == 'present':
            if not policy_identifier:
                module.fail_json(msg="Either 'title' or 'policy_id' is required for present state")
            
            # Build desired data
            desired_data = {
                'title': policy_identifier
            }
            
            # Add optional fields
            if description is not None:
                desired_data['description'] = description
            if disabled is not None:
                desired_data['disabled'] = disabled
            if filter_criteria is not None:
                desired_data['filter_criteria'] = filter_criteria
            if breaking_criteria is not None:
                desired_data['breaking_criteria'] = breaking_criteria
            if group_severity:
                desired_data['group_severity'] = group_severity
            if group_status:
                desired_data['group_status'] = group_status
            if group_assignee:
                desired_data['group_assignee'] = group_assignee
            if group_title:
                desired_data['group_title'] = group_title
            if group_description:
                desired_data['group_description'] = group_description
            if split_by_field:
                desired_data['split_by_field'] = split_by_field
            if priority is not None:
                desired_data['priority'] = priority
            if rules is not None:
                desired_data['rules'] = rules
            
            # Add additional fields
            if additional_fields:
                desired_data.update(additional_fields)
            
            if module.check_mode:
                # Determine if this would be a create or update operation
                existing_status, existing_data = get_aggregation_policy(conn, policy_identifier)
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
                ensure_present(conn, policy_identifier, desired_data, result)

        elif state == 'absent':
            if not policy_identifier:
                module.fail_json(msg="Either 'title' or 'policy_id' is required for absent state")
            
            # Check if aggregation policy exists via EMI
            existing_status, existing_data = get_aggregation_policy(conn, policy_identifier)
            
            if existing_status == 200:
                # Delete aggregation policy
                if module.check_mode:
                    result.update({
                        'changed': True,
                        'status': 204,
                        'operation': 'delete',
                        'body': ''
                    })
                else:
                    status, data = delete_aggregation_policy(conn, policy_identifier)
                    result.update({
                        'changed': status == 204,
                        'status': status,
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
                    'body': 'Aggregation policy already absent'
                })

        # Return results
        module.exit_json(**result)

    except Exception as e:
        module.fail_json(
            msg=f"Exception occurred: {str(e)}",
            title=module.params.get('title'),
            policy_id=module.params.get('policy_id'),
            state=module.params.get('state')
        )


if __name__ == '__main__':
    main()