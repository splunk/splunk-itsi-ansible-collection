#!/usr/bin/python
# -*- coding: utf-8 -*-

# (c) 2025 Splunk ITSI Ansible Collection maintainers
# GPL-3.0-or-later

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
---
module: add_episode_comments
short_description: Add comments to Splunk ITSI episodes
description:
  - Add comments to existing episodes in Splunk IT Service Intelligence (ITSI).
  - Comments are associated with a specific episode ID and can provide context or status updates.
  - Uses the response format returning status, headers, and body for comprehensive API interaction.
version_added: "1.0.0"
author:
  - "splunk.itsi maintainers"
options:
  event_id:
    description:
      - The episode ID to add a comment to.
      - This should be the _key field from an episode, such as returned by notable_event_group_info.
    type: str
    required: true
  comment:
    description:
      - The text content of the comment to add to the episode.
      - Can contain any text content describing actions taken, status updates, or other relevant information.
    type: str
    required: true
  is_group:
    description:
      - Whether this comment is for an episode group.
      - Should be set to true for ITSI episodes (notable event groups).
    type: bool
    default: true

requirements:
  - Connection configuration requires C(ansible_connection=httpapi) and C(ansible_network_os=splunk.itsi.itsi_api_client).
  - Authentication via Bearer token, session key, or username/password as documented in the httpapi plugin.
notes:
  - This module adds comments to existing ITSI episodes using the notable_event_comment endpoint.
  - The episode must exist before adding comments to it.
  - Comments are permanently associated with the episode and cannot be deleted via API.
  - Use notable_event_group_info module to retrieve episode IDs for commenting.
"""

EXAMPLES = r"""
# Add a simple comment to an episode
- name: Add comment to episode
  splunk.itsi.add_episode_comments:
    event_id: "ff942149-4e70-42ff-94d3-6fdf5c5f95f3"
    comment: "Investigating root cause - checking application logs"

# Add a comment with variable content
- name: Add dynamic comment to episode
  splunk.itsi.add_episode_comments:
    event_id: "{{ episode_id }}"
    comment: "{{ comment_text }}"
    is_group: true

# Add comment using episode data from previous task
- name: Get episodes and add comment to first one
  block:
    - name: Get episode list
      splunk.itsi.notable_event_group_info:
        filter_data:
          limit: 1
      register: episodes_result
    
    - name: Add comment to first episode
      splunk.itsi.add_episode_comments:
        event_id: "{{ episodes_result.body.entry[0]._key }}"
        comment: "Automated comment from Ansible playbook"
      when: episodes_result.body.entry | length > 0

# Error handling with status checking
- name: Add comment with error handling
  splunk.itsi.add_episode_comments:
    event_id: "{{ target_episode_id }}"
    comment: "Issue resolved - monitoring for recurrence"
  register: comment_result
  failed_when: comment_result.status != 200

- name: Show comment result
  debug:
    msg: "Comment added successfully with status {{ comment_result.status }}"
  when: comment_result.status == 200
"""

RETURN = r"""
status:
  description: HTTP status code from the ITSI API response
  type: int
  returned: always
  sample: 200
headers:
  description: HTTP response headers from the ITSI API
  type: dict
  returned: always
  sample:
    Content-Type: "application/json"
    Server: "Splunkd"
body:
  description: Response body from the ITSI API
  type: str
  returned: always
  sample: '{"success": true, "message": "Comment added successfully"}'
comment_data:
  description: The comment data that was sent to the API
  type: dict
  returned: always
  sample:
    comment: "Investigating root cause"
    event_id: "ff942149-4e70-42ff-94d3-6fdf5c5f95f3"
    is_group: true
"""

import json

from ansible.module_utils.basic import AnsibleModule, to_text
from ansible.module_utils.connection import Connection, ConnectionError
from ansible.module_utils.six.moves.urllib.error import HTTPError  # type: ignore


def add_episode_comment(conn, event_id, comment, is_group=True):
    """Add a comment to an ITSI episode.
    
    Args:
        conn: Connection object from AnsibleModule
        event_id: Episode ID to add comment to
        comment: Comment text to add
        is_group: Whether this is a group comment (default True for episodes)
        
    Returns:
        tuple: (status_code, result_dict)
    """
    # Build the comment data payload
    comment_data = {
        "comment": comment,
        "event_id": event_id,
        "is_group": is_group
    }
    
    # Convert to JSON for POST request
    json_data = json.dumps(comment_data)
    
    try:
        # Use the connection's RPC mechanism to call send_request on httpapi plugin
        result = conn.send_request(
            "/servicesNS/nobody/SA-ITOA/event_management_interface/notable_event_comment",
            json_data,
            method="POST"
        )
        
        # Always expect response format (Python dict with status, headers, body)
        if not isinstance(result, dict):
            return 500, {"error": f"Expected enhanced response dict from send_request. Received {type(result)}: '{result}'."}
            
        # Validate response format
        if "status" not in result or "body" not in result:
            return 500, {"error": f"Invalid enhanced response format. Missing 'status' or 'body' fields. Received: {result}"}

        # Extract response components
        status = result["status"]
        headers = result.get("headers", {})
        body = result["body"]
        
        # Add the comment data that was sent for reference
        result_with_data = result.copy()
        result_with_data['comment_data'] = comment_data
        
        return status, result_with_data
        
    except ConnectionError as e:
        return 500, {"error": f"Connection error: {to_text(e)}"}
    except HTTPError as e:
        return getattr(e, "code", 500), {"error": f"HTTP error: {to_text(e)}"}
    except Exception as e:
        return 500, {"error": f"Unexpected error: {to_text(e)}"}


def main():
    """Main module execution."""
    # Define module arguments
    module_args = dict(
        event_id=dict(type='str', required=True),
        comment=dict(type='str', required=True),
        is_group=dict(type='bool', default=True),
    )

    # Create AnsibleModule instance
    module = AnsibleModule(
        argument_spec=module_args,
        supports_check_mode=False
    )

    try:
        # Get connection to httpapi plugin
        conn = Connection(module._socket_path)
        
        # Extract parameters
        event_id = module.params['event_id']
        comment = module.params['comment']
        is_group = module.params.get('is_group', True)
        
        # Add comment to episode
        status, result = add_episode_comment(
            conn, event_id, comment, is_group
        )
        
        # Check if the request was successful
        if status == 200:
            # Success - return the response
            module.exit_json(
                changed=True,
                **result
            )
        else:
            # API returned an error status
            module.fail_json(
                msg=f"Failed to add comment - HTTP {status}",
                **result
            )
            
    except Exception as e:
        # Handle any unexpected exceptions
        module.fail_json(
            msg=f"Error adding episode comment: {str(e)}",
            exception=str(e)
        )


if __name__ == '__main__':
    main()