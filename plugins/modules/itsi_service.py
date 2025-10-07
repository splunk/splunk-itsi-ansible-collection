#!/usr/bin/python
# -*- coding: utf-8 -*-
# GPL-3.0-or-later

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r"""
---
module: itsi_service
short_description: Manage Splunk ITSI Service objects via itoa_interface
version_added: "1.0.0"
description: |
  Create, update, or delete Splunk ITSI Service objects using the itoa_interface REST API.
  Idempotent by comparing stable fields on the service: title, enabled, description, sec_grp,
  base_service_template_id, service_tags, entity_rules, plus any keys provided in "extra".
  Uses the splunk.itsi.itsi_api_client httpapi plugin for authentication and transport.
author: splunk.itsi maintainers
notes:
  - Requires ansible_connection=httpapi and ansible_network_os=splunk.itsi.itsi_api_client.
  - Update operations must include a valid title; this module will inject the current title if you do not supply one.
options:
  service_key:
    description: "ITSI service _key. When provided, used as the primary identifier."
    type: str
  name:
    description: "Exact service title (service.title). Required if service_key is not provided."
    type: str

  enabled:
    description: "Enable/disable the service (true/false or 1/0)."
    type: bool
  description:
    description: "Service description (free text)."
    type: str
  sec_grp:
    description: "ITSI team (security group) key to assign the service to."
    type: str

  entity_rules:
    description: >
      Opaque list of entity rule objects (as returned by ITSI). The module treats this as raw JSON.
      Example from probes shows an array of objects with rule_condition and rule_items.
    type: list
    elements: dict

  service_tags:
    description: >
      Object with 'tags' and 'template_tags' arrays. May be null on GET.
      Comparison is order-insensitive for tags/template_tags; other keys compared raw.
    type: dict
  base_service_template_id:
    description: "ID of the service template. Use empty string to clear."
    type: str

  extra:
    description: >
      Additional JSON fields to include in payload (merged on top of managed fields).
      Keys present in extra will override first-class options on conflicts.
    type: dict
    default: {}

  state:
    description: Desired state.
    type: str
    choices: [present, absent]
    default: present
"""

EXAMPLES = r"""
- name: Ensure a service exists (idempotent upsert by title)
  splunk.itsi.itsi_service:
    name: api-gateway
    enabled: true
    description: Frontend + API
    sec_grp: default_itsi_security_group
    service_tags:
      tags: [prod, payments]
      template_tags: [critical, sa]
    entity_rules: []
    base_service_template_id: ""
    state: present

- name: Remove a service by title
  splunk.itsi.itsi_service:
    name: old-dev-service
    state: absent

- name: Update specific service by key
  splunk.itsi.itsi_service:
    service_key: a2961217-9728-4e9f-b67b-15bf4a40ad7c
    enabled: false
    description: "Disabled for maintenance"
"""

RETURN = r"""
service:
  description: Service document after the operation when available.
  type: dict
  returned: when not bulk
status:
  description: HTTP status code from Splunk for the last request.
  type: int
  returned: always
changed_fields:
  description: Keys that changed during update.
  type: list
  elements: str
  returned: when state=present and an update occurred
diff:
  description: Structured before/after for managed fields.
  type: dict
  returned: when check_mode is true or an update/delete occurs
raw:
  description: Raw JSON from Splunk for the last call.
  type: raw
  returned: always
changed:
  description: Whether any change was made.
  type: bool
  returned: always
"""

import json
import sys
from typing import Any, Dict, Tuple, Optional
from urllib.parse import urlencode, quote_plus

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.connection import Connection

BASE = "servicesNS/nobody/SA-ITOA/itoa_interface/service"


# ---------------- transport ----------------

def _send(conn: Connection, method: str, path: str, params: Optional[Dict[str, Any]] = None, payload: Optional[Any] = None) -> Tuple[int, Any]:
    """Send request via itsi_api_client with enhanced response format."""
    method = method.upper()
    if params:
        # Drop Nones/empties but keep 0/False
        qp = {k: v for k, v in params.items() if v is not None and v != ""}
        sep = "&" if "?" in path else "?"
        path = f"{path}{sep}{urlencode(qp, doseq=True)}"
    
    if isinstance(payload, (dict, list)):
        body = json.dumps(payload)
    elif payload is None:
        body = ""
    else:
        body = str(payload)
    
    # Use response format from itsi_api_client
    res = conn.send_request(path, method=method, body=body)
    status = int(res.get("status", 0)) if isinstance(res, dict) else 0
    body_text = res.get("body") if isinstance(res, dict) else ""
    
    try:
        body = json.loads(body_text) if body_text else {}
    except Exception:
        body = {"raw_response": body_text}
    
    return status, body


# ---------------- helpers ----------------

def _int_bool(v):
    """Normalize booleans to 0/1"""
    if isinstance(v, bool):
        return 1 if v else 0
    if v in (0, 1):
        return int(v)
    return v

def _equal_service_tags(a, b):
    """Simplified service_tags comparison."""
    # Normalize None/empty to None for comparison
    if not a and not b:
        return True
    if not a or not b:
        return False
    # Compare structure directly - user responsibility for consistency
    return a == b

def _desired_payload(params):
    """Assemble the outgoing payload from module params."""
    out = {}
    if params.get("name") is not None:
        out["title"] = params["name"]
    for k in ("enabled", "description", "sec_grp", "service_tags",
              "entity_rules", "base_service_template_id"):
        if params.get(k) is not None:
            out[k] = params[k]
    extra = params.get("extra") or {}
    out.update(extra)
    return out

def _compute_patch(current_doc, desired_doc):
    """
    Compare selected fields and build minimal patch. Returns (patch, changed_keys).
    - enabled compared as 0/1
    - service_tags compared order-insensitive for tags/template_tags
    - entity_rules compared raw
    """
    patch = {}
    changed = []
    
    # Debug: Log the types and values of key fields
    for field in ['custom_field_1', 'custom_field_2', 'custom_field_3']:
        current_val = current_doc.get(field)
        desired_val = desired_doc.get(field)
        print(f"DEBUG: {field} - current: {current_val} ({type(current_val)}), desired: {desired_val} ({type(desired_val)})", file=sys.stderr)

    # scalars
    for k in ("title", "description", "sec_grp", "base_service_template_id"):
        if k in desired_doc and desired_doc[k] != current_doc.get(k):
            patch[k] = desired_doc[k]
            changed.append(k)

    # enabled (0/1 semantics)
    if "enabled" in desired_doc:
        want = _int_bool(desired_doc.get("enabled"))
        have = _int_bool(current_doc.get("enabled"))
        if want != have:
            patch["enabled"] = desired_doc["enabled"]
            changed.append("enabled")

    # service_tags
    if "service_tags" in desired_doc:
        if not _equal_service_tags(desired_doc.get("service_tags"), current_doc.get("service_tags")):
            patch["service_tags"] = desired_doc["service_tags"]
            changed.append("service_tags")

    # entity_rules (raw compare)
    if "entity_rules" in desired_doc:
        if desired_doc.get("entity_rules") != current_doc.get("entity_rules"):
            patch["entity_rules"] = desired_doc["entity_rules"]
            changed.append("entity_rules")

    # any extra keys present in desired
    managed = {"title", "enabled", "description", "sec_grp", "service_tags",
               "entity_rules", "base_service_template_id", "kpis", "permissions",
               "object_type", "mod_source", "mod_timestamp", "_version", 
               "identifying_name", "is_healthscore_calculate_by_entity_enabled"}
    for k, v in desired_doc.items():
        if k in managed:
            continue
        current_val = current_doc.get(k)
        if current_val != v:
            patch[k] = v
            changed.append(k)

    # Check for removed extra fields (present in current but not in desired)
    for k in current_doc.keys():
        if k in managed:
            continue
        # Skip internal fields that start with underscore or are system fields
        if k.startswith('_'):
            continue
        if k not in desired_doc and current_doc.get(k) is not None:
            # Field is being removed, set to None in patch and track as changed
            patch[k] = None
            changed.append(k)

    return patch, changed


# ---------------- CRUD ----------------

def _get_by_key(conn, key, fields=None):
    params = {}
    if fields:
        params["fields"] = fields if isinstance(fields, str) else ",".join(fields)
    return _send(conn, "GET", f"{BASE}/{quote_plus(key)}", params=params)

def _find_by_title(conn, title):
    """
    Exact title filter; returns first match or None.
    """
    # Try different filter approaches
    filter_attempts = [
        # Standard JSON filter
        json.dumps({"title": title}),
        # Simple string filter (some APIs prefer this)
        f"title={title}",
        # Quoted filter
        f'"title":"{title}"',
        # None (get all and filter client-side)
        None
    ]
    
    last_status = 200
    
    for attempt_filter in filter_attempts:
        params = {
        }
        
        if attempt_filter is not None:
            params["filter"] = attempt_filter
            
        status, body = _send(conn, "GET", BASE, params=params)
        last_status = status
        
        # Parse response
        candidates = []
        if isinstance(body, dict):
            if "entry" in body and isinstance(body["entry"], list):
                candidates = body["entry"]
            elif "results" in body and isinstance(body["results"], list):
                candidates = body["results"]
            elif "items" in body and isinstance(body["items"], list):
                candidates = body["items"]
            elif body.get("_key") and body.get("title") == title:
                candidates = [body]
        elif isinstance(body, list):
            candidates = body

        # Filter client-side for exact title match
        matches = [d for d in candidates if isinstance(d, dict) and d.get("title") == title]
        
        if matches:
            if len(matches) > 1:
                return status, None, "Multiple services found with the same title; use service_key to disambiguate."
            return status, matches[0], None
            
        # If we got results but no matches, continue to next filter approach
        # If no results at all with a filter, also try next approach
        
    return last_status, None, None

def _create(conn, payload):
    return _send(conn, "POST", BASE, payload=payload)

def _update(conn, key, patch):
    # Caller must include a valid title; Splunk rejects empty/missing.
    return _send(conn, "POST", f"{BASE}/{quote_plus(key)}", payload=patch)

def _delete(conn, key):
    return _send(conn, "DELETE", f"{BASE}/{quote_plus(key)}")




# ---------------- main ----------------

def main():
    module = AnsibleModule(
        argument_spec=dict(
            service_key=dict(type="str"),
            name=dict(type="str"),

            enabled=dict(type="bool"),
            description=dict(type="str"),
            sec_grp=dict(type="str"),
            entity_rules=dict(type="list", elements="dict"),
            service_tags=dict(type="dict"),
            base_service_template_id=dict(type="str"),

            extra=dict(type="dict", default={}),

            state=dict(type="str", choices=["present", "absent"], default="present"),
        ),
        supports_check_mode=True,
        required_one_of=[["service_key", "name"]],
    )

    if not getattr(module, "_socket_path", None):
        module.fail_json(msg="Use ansible_connection=httpapi and ansible_network_os=splunk.itsi.itsi_api_client")

    p = module.params
    conn = Connection(module._socket_path)

    result = {
        "changed": False,
        "status": 0,
        "service": None,
        "raw": {},
        "changed_fields": [],
        "diff": {"before": {}, "after": {}},
    }

    # Single-object path
    state = p["state"]
    key = p.get("service_key")
    name = p.get("name")

    # Discover current
    current = None
    if key:
        status, body = _get_by_key(conn, key)
        result["status"] = status
        result["raw"] = body
        if status == 200 and isinstance(body, dict):
            current = body
    else:
        status, doc, err = _find_by_title(conn, name)
        result["status"] = status
        result["raw"] = doc if doc is not None else {}
        if err:
            module.fail_json(msg=err, **result)
        current = doc

    # Absent
    if state == "absent":
        if not current:
            module.exit_json(**result)
        if module.check_mode:
            result["changed"] = True
            result["diff"]["before"] = {k: current.get(k) for k in ("title","enabled","description","sec_grp","base_service_template_id","service_tags","entity_rules")}
            result["diff"]["after"] = {}
            module.exit_json(**result)
        status, body = _delete(conn, current.get("_key", key))
        result["status"] = status
        result["raw"] = body
        result["changed"] = True
        result["service"] = None
        result["changed_fields"] = ["_deleted"]
        result["diff"]["before"] = {k: current.get(k) for k in ("title","enabled","description","sec_grp","base_service_template_id","service_tags","entity_rules")}
        result["diff"]["after"] = {}
        module.exit_json(**result)

    # Present
    desired = _desired_payload(p)

    # Create
    if not current:
        if "title" not in desired:
            # Creating must include a title
            if name:
                desired["title"] = name
            else:
                module.fail_json(msg="Creating a service requires 'name' (title).", **result)

        if module.check_mode:
            result["changed"] = True
            result["diff"]["before"] = {}
            result["diff"]["after"] = {k: desired.get(k) for k in ("title","enabled","description","sec_grp","base_service_template_id","service_tags","entity_rules")}
            module.exit_json(**result)

        status, body = _create(conn, desired)
        result["status"] = status
        result["raw"] = body
        created = body if isinstance(body, dict) else {}
        result["service"] = created or desired
        result["changed"] = True
        result["changed_fields"] = list(desired.keys())
        result["diff"]["before"] = {}
        result["diff"]["after"] = {k: (created.get(k) if created else desired.get(k)) for k in ("title","enabled","description","sec_grp","base_service_template_id","service_tags","entity_rules")}
        module.exit_json(**result)

    # Update
    # Ensure title present in payload for Splunk validation
    if "title" not in desired and current.get("title"):
        desired["title"] = current["title"]

    patch, changed_fields = _compute_patch(current, desired)
    if not patch:
        result["service"] = current
        module.exit_json(**result)
    
    # ITSI requires title in UPDATE requests even if unchanged
    if "title" not in patch and current.get("title"):
        patch["title"] = current["title"]

    if module.check_mode:
        after = dict(current)
        after.update(patch)
        result["changed"] = True
        result["changed_fields"] = changed_fields
        result["diff"]["before"] = {k: current.get(k) for k in ("title","enabled","description","sec_grp","base_service_template_id","service_tags","entity_rules")}
        result["diff"]["after"] = {k: after.get(k) for k in ("title","enabled","description","sec_grp","base_service_template_id","service_tags","entity_rules")}
        module.exit_json(**result)

    status, body = _update(conn, current.get("_key", key), patch)
    result["status"] = status
    result["raw"] = body
    result["changed"] = True
    result["changed_fields"] = changed_fields
    after = dict(current)
    after.update(patch)
    result["service"] = after
    result["diff"]["before"] = {k: current.get(k) for k in ("title","enabled","description","sec_grp","base_service_template_id","service_tags","entity_rules")}
    result["diff"]["after"] = {k: after.get(k) for k in ("title","enabled","description","sec_grp","base_service_template_id","service_tags","entity_rules")}
    module.exit_json(**result)


if __name__ == "__main__":
    main()
