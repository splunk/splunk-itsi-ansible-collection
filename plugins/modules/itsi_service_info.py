#!/usr/bin/python
# -*- coding: utf-8 -*-

# (c) 2025 Splunk ITSI Ansible Collection maintainers
# GPL-3.0-or-later

from __future__ import annotations

__metaclass__ = type

DOCUMENTATION = r"""
---
module: itsi_service_info
short_description: Gather facts about Splunk ITSI Service objects via itoa_interface
version_added: "1.0.0"
description: |
  Read service documents from the Splunk ITSI REST API (itoa_interface).
  You can fetch by key, fetch by exact title, or list with server-side filters.
  Uses the splunk.itsi.itsi_api_client httpapi plugin for transport and auth.
author: splunk.itsi maintainers
notes:
  - Requires ansible_connection=httpapi and ansible_network_os=splunk.itsi.itsi_api_client.
  - This is a read-only module. It never changes remote state.
options:
  service_key:
    description:
      - Exact ITSI service _key to fetch.
    type: str
  title:
    description:
      - Exact service title to match. If both service_key and title are provided, service_key wins.
    type: str
  enabled:
    description:
      - Optional filter on enabled state.
    type: bool
  sec_grp:
    description:
      - Optional team (security group) filter. Exact match.
    type: str
  filter:
    description:
      - Raw server-side filter object merged with simple filters when possible.
      - Use this for advanced queries such as regex title matches.
    type: dict
  fields:
    description:
      - Projection of fields to return. Comma-separated string or list of strings.
    type: raw
  count:
    description:
      - Page size for listings. Ignored for fetch by key or title.
    type: int
  offset:
    description:
      - Offset for listings.
    type: int
"""

EXAMPLES = r"""
- name: List all services
  splunk.itsi.itsi_service_info:
  register: out

- name: Fetch by exact title
  splunk.itsi.itsi_service_info:
    title: api-gateway
  register: svc_by_title

- name: Fetch by key with projection
  splunk.itsi.itsi_service_info:
    service_key: a2961217-9728-4e9f-b67b-15bf4a40ad7c
    fields: _key,title,enabled,sec_grp,entity_rules
  register: svc_by_key

- name: Filtered list
  splunk.itsi.itsi_service_info:
    enabled: true
    sec_grp: default_itsi_security_group
  register: filtered

- name: Paginated list
  splunk.itsi.itsi_service_info:
    count: 3
    offset: 0
  register: page1
"""

RETURN = r"""
services:
  description: List of service objects returned by the ITSI API.
  type: list
  elements: dict
  returned: always
service:
  description: First item from services when a single result is expected.
  type: dict
  returned: when a single result is found
status:
  description: HTTP status from the last request.
  type: int
  returned: always
raw:
  description: Raw body parsed from the server response for the last call.
  type: raw
  returned: always
changed:
  description: Always false. This is an information module.
  type: bool
  returned: always
"""

import json
from typing import Any, Dict, Tuple, Optional
from urllib.parse import urlencode, quote_plus

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.connection import Connection

BASE = "servicesNS/nobody/SA-ITOA/itoa_interface/service"


def _send(conn: Connection, method: str, path: str, params: Optional[Dict[str, Any]] = None) -> Tuple[int, Any]:
    """Send request via itsi_api_client."""
    method = method.upper()
    if params:
        # Drop Nones/empties but keep 0/False
        qp = {k: v for k, v in params.items() if v is not None and v != ""}
        sep = "&" if "?" in path else "?"
        path = f"{path}{sep}{urlencode(qp, doseq=True)}"
    
    # Use response format from itsi_api_client
    res = conn.send_request(path, "", method=method)
    status = int(res.get("status", 0)) if isinstance(res, dict) else 0
    body_text = res.get("body") if isinstance(res, dict) else ""
    
    try:
        body = json.loads(body_text) if body_text else {}
    except Exception:
        body = {"raw_response": body_text}
    
    return status, body


def _build_filter(p: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Build server-side filter. If both simple options and `filter` specify the same key, the
    filter object takes precedence."""
    f = dict(p.get("filter") or {})
    if p.get("title") is not None and "title" not in f:
        f["title"] = p["title"]
    if p.get("enabled") is not None and "enabled" not in f:
        f["enabled"] = 1 if p["enabled"] is True else 0
    if p.get("sec_grp") is not None and "sec_grp" not in f:
        f["sec_grp"] = p["sec_grp"]
    return f or None


def main():
    module = AnsibleModule(
        argument_spec=dict(
            service_key=dict(type="str"),
            title=dict(type="str"),
            enabled=dict(type="bool"),
            sec_grp=dict(type="str"),
            filter=dict(type="dict"),
            fields=dict(type="list", elements="str"),
            count=dict(type="int"),
            offset=dict(type="int"),
        ),
        supports_check_mode=True,
    )

    if not getattr(module, "_socket_path", None):
        module.fail_json(msg="Use ansible_connection=httpapi and ansible_network_os=splunk.itsi.itsi_api_client")

    conn = Connection(module._socket_path)
    p = module.params

    result: Dict[str, Any] = {
        "changed": False,
        "status": 0,
        "raw": {},
    }

    # Direct GET by key
    if p.get("service_key"):
        status, body = _send(conn, "GET", f"{BASE}/{quote_plus(p['service_key'])}")
        result["status"] = status
        result["raw"] = body
        if isinstance(body, dict) and status != 200:
            # Handle different error response formats
            if "message" in body:
                result["error"] = body.get("message")
            elif "error" in body:
                result["error"] = body.get("error")
            
            # Add error context if available
            if "context" in body:
                result["error_context"] = body.get("context")
            elif "details" in body:
                result["error_context"] = body.get("details")
                
            # Only add request debugging on errors for troubleshooting
            result["request"] = {"path": f"{BASE}/{quote_plus(p['service_key'])}", "params": {}}
        elif isinstance(body, dict):
            result["service"] = body
        module.exit_json(**result)

    # List path with parameter handling
    params: Dict[str, Any] = {}
    if p.get("fields"):
        # ITSI expects comma-separated fields string
        # stringify, dedupe, and preserve order of first appearance
        seen = set()
        fld_list = []
        for x in p["fields"]:
            s = str(x)
            if s not in seen:
                seen.add(s)
                fld_list.append(s)
        if fld_list:
            params["fields"] = ",".join(fld_list)
    fobj = _build_filter(p)
    if fobj:
        params["filter"] = json.dumps(fobj, separators=(",", ":"))
    if p.get("count") is not None:
        params["count"] = p["count"]
    if p.get("offset") is not None:
        params["offset"] = p["offset"]

    status, body = _send(conn, "GET", BASE, params=params)
    result["status"] = status
    result["raw"] = body

    # Handles multiple response patterns
    if isinstance(body, dict) and status != 200:
        if "message" in body:
            result["error"] = body.get("message")
        elif "error" in body:
            result["error"] = body.get("error")
        
        # Add error context if available
        if "context" in body:
            result["error_context"] = body.get("context")
        elif "details" in body:
            result["error_context"] = body.get("details")
            
        # Only add request debugging on errors for troubleshooting
        result["request"] = {"path": BASE, "params": params}
    elif isinstance(body, list):
        result["items"] = body
    elif isinstance(body, dict) and "items" in body and "size" in body:
        # Preserve envelope AND also expose items for paging
        result["paging"] = {"size": body.get("size"), "items": body.get("items")}
        result["items"] = body.get("items", [])
    else:
        # Unknown shape: return as-is for troubleshooting
        result["items"] = body if isinstance(body, list) else []
        
    module.exit_json(**result)


if __name__ == '__main__':
    main()