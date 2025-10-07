#!/usr/bin/python
# -*- coding: utf-8 -*-
# GPLv3+

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r"""
---
module: notable_event_group_info
short_description: Read Splunk ITSI notable_event_group (episodes)
description: >
  Reads a single episode by _key, lists episodes, or returns only a count using the ITSI Event Management Interface.
  Requires ansible_connection=httpapi and ansible_network_os=splunk.itsi.itsi_api_client.
version_added: "1.0.0"
author: "splunk.itsi maintainers"
options:
  episode_id:
    description: "ITSI notable_event_group _key. When provided, fetches a single episode."
    type: str
  limit:
    description: "Max entries to return when listing (ITSI parameter 'limit'). 0 means no limit param is sent."
    type: int
    default: 0
  skip:
    description: "Number of entries to skip from the start (ITSI parameter 'skip')."
    type: int
  fields:
    description: "Comma-separated list of field names to include (ITSI parameter 'fields')."
    type: str
  filter_data:
    description: "MongoDB-style JSON string to filter results (ITSI parameter 'filter_data'). Example: '{\"status\":\"2\"}'."
    type: str
  sort_key:
    description: "Field name to sort by (ITSI parameter 'sort_key')."
    type: str
  sort_dir:
    description: "Sort direction (ITSI parameter 'sort_dir'). Use 1 for ascending, 0 for descending."
    type: int
    choices:
      - 0
      - 1
  count_only:
    description: "If true, call the '/count' endpoint and return only a numeric count."
    type: bool
    default: false
notes:
  - "Connection/auth/SSL config is provided by httpapi (inventory), not by this module."
requirements:
  - ansible.netcommon
"""

EXAMPLES = r"""
- name: List first 10 episodes
  hosts: splunk
  gather_facts: false
  tasks:
    - name: List
      splunk.itsi.notable_event_group_info:
        limit: 10
      register: out
    - ansible.builtin.debug:
        var: out.episodes

- name: Count open episodes (status=2)
  hosts: splunk
  gather_facts: false
  tasks:
    - name: Count
      splunk.itsi.notable_event_group_info:
        count_only: true
        filter_data: "{\\"status\\":\\"2\\"}"
      register: cnt
    - ansible.builtin.debug:
        var: cnt.count

- name: Get one episode by _key
  hosts: splunk
  gather_facts: false
  tasks:
    - name: Fetch
      splunk.itsi.notable_event_group_info:
        episode_id: 000f91af-ac7d-45e2-a498-5c4b6fe96431
      register: one
    - ansible.builtin.debug:
        var: one.episodes

- name: Advanced filtering with status and error handling
  hosts: splunk
  gather_facts: false
  tasks:
    - name: List high-severity episodes with pagination
      splunk.itsi.notable_event_group_info:
        filter_data: "{\\"severity\\": {\\"$in\\": [\\"1\\", \\"2\\", \\"3\\"]}}"
        sort_key: "mod_time"
        sort_dir: 0
        limit: 20
        skip: 0
        fields: "_key,title,severity,status,mod_time"
      register: result
    
    - name: Check HTTP status and handle errors
      ansible.builtin.fail:
        msg: "API request failed with status {{ result.status }}"
      when: result.status != 200
    
    - name: Display episodes and metadata
      ansible.builtin.debug:
        msg: |
          Found {{ result.episodes | length }} episodes
          HTTP Status: {{ result.status }}
          Total raw response keys: {{ result.raw.keys() | list }}
"""

RETURN = r"""
episodes:
  description: "Episode list (empty when count_only=true)."
  type: list
  elements: dict
  returned: when count_only is false
count:
  description: "Count of objects matching filter (when count_only=true)."
  type: int
  returned: when count_only is true
raw:
  description: "Raw JSON response (dict) returned by Splunk ITSI."
  type: dict
  returned: always
status:
  description: "HTTP status code returned by Splunk."
  type: int
  returned: always
changed:
  description: "Always false (read-only)."
  type: bool
  returned: always
"""

import json
from urllib.parse import urlencode, quote_plus

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.connection import Connection
from ansible.module_utils.six.moves.urllib.error import HTTPError  # type: ignore

BASE = "servicesNS/nobody/SA-ITOA/event_management_interface/notable_event_group"


def _send_request(conn: Connection, method: str, path: str, params=None, payload=None):
    """
    Call Splunk via the httpapi plugin.
    """
    method = method.upper()

    # Build query string from params
    def _append_query(path: str, query: dict) -> str:
        q = {k: v for (k, v) in (query or {}).items() if v is not None and v != "" and v is not False}
        if not q:
            return path
        sep = "&" if "?" in path else "?"
        return f"{path}{sep}{urlencode(q, doseq=True)}"

    full_path = _append_query(path, params or {})

    # Prepare body data
    if isinstance(payload, (dict, list)):
        body = json.dumps(payload)
    elif payload is None:
        body = ""
    else:
        body = str(payload)

    try:
        # Use the connection's RPC mechanism to call send_request on httpapi plugin
        result = conn.send_request(full_path, body, method=method)
        
        # Always expect response format (Python dict with status, headers, body)
        if not isinstance(result, dict):
            return 500, {"error": f"Expected response dict from send_request('{full_path}', '{body}', method='{method}'). Received {type(result)}: '{result}'."}
            
        # Validate response format
        if "status" not in result or "body" not in result:
            return 500, {"error": f"Invalid response format from send_request('{full_path}', '{body}', method='{method}'). Missing 'status' or 'body' fields. Received: {result}"}

        # Extract response components
        status = result["status"]
        headers = result.get("headers", {})
        body_text = result["body"]
        
        # Parse the actual response body
        if body_text:
            try:
                data = json.loads(body_text)
            except ValueError:
                data = {"raw_response": body_text}
        else:
            data = {}
        
        return status, data
            
    except Exception as e:
        error_text = str(e)
        
        # String-based error detection for fallback cases
        if "401" in error_text or "Unauthorized" in error_text:
            return 401, {"error": "Authentication failed"}
        elif "404" in error_text or "Not Found" in error_text:
            return 404, {"error": "Endpoint not found"}
        else:
            return 500, {"error": error_text}


def main():
    module = AnsibleModule(
        argument_spec=dict(
            episode_id=dict(type="str"),
            limit=dict(type="int", default=0),
            skip=dict(type="int"),
            fields=dict(type="str"),
            filter_data=dict(type="str"),
            sort_key=dict(type="str"),
            sort_dir=dict(type="int", choices=[0, 1]),
            count_only=dict(type="bool", default=False),
        ),
        supports_check_mode=True,
    )

    if not getattr(module, "_socket_path", None):
        module.fail_json(msg="Use ansible_connection=httpapi and ansible_network_os=splunk.itsi.itsi_api_client")

    p = module.params
    conn = Connection(module._socket_path)

    # Single-object GET by _key
    if p["episode_id"] and not p["count_only"]:
        eid = quote_plus(p["episode_id"])
        status, body = _send_request(conn, "GET", f"{BASE}/{eid}")
        # ITSI EMI returns single episode object directly - wrap in list for consistent interface
        episodes = [] if status != 200 else [body] if isinstance(body, dict) else []
        module.exit_json(changed=False, status=status, raw=body, episodes=episodes)

    # Count endpoint
    if p["count_only"]:
        params = {}
        if p["filter_data"]:
            params["filter_data"] = p["filter_data"]
        status, body = _send_request(conn, "GET", f"{BASE}/count", params=params)
        count = 0
        if isinstance(body, dict) and "count" in body:
            try:
                count = int(body["count"])
            except (TypeError, ValueError):
                count = 0
        module.exit_json(changed=False, status=status, raw=body, count=count)

    # List endpoint (must end with '/')
    params = {}
    if p["limit"] and p["limit"] > 0:
        params["limit"] = p["limit"]
    if p["skip"] is not None:
        params["skip"] = p["skip"]
    if p["fields"]:
        params["fields"] = p["fields"]
    if p["filter_data"]:
        params["filter_data"] = p["filter_data"]
    if p["sort_key"]:
        params["sort_key"] = p["sort_key"]
    if p["sort_dir"] is not None:
        params["sort_dir"] = p["sort_dir"]

    status, body = _send_request(conn, "GET", BASE + "/", params=params)
    episodes = body if isinstance(body, list) else []
    module.exit_json(changed=False, status=status, raw=body, episodes=episodes)


if __name__ == "__main__":
    main()
