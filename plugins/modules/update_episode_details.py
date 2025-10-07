#!/usr/bin/python
# -*- coding: utf-8 -*-

# (c) 2025 Splunk ITSI Ansible Collection maintainers
# GPL-3.0-or-later

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
---
module: update_episode_details
short_description: Update specific fields of Splunk ITSI episodes
description:
  - Update specific fields of existing episodes in Splunk IT Service Intelligence (ITSI).
  - Uses partial data updates to modify only the specified fields without affecting other episode data.
  - Supports common episode fields like severity, status, owner, and instruction.
  - Uses response format returning status, headers, and body for comprehensive API interaction.
version_added: "1.0.0"
author:
  - "splunk.itsi maintainers"
options:
  episode_id:
    description:
      - The episode ID (_key field) to update.
      - This should be the _key field from an episode, such as returned by notable_event_group_info.
    type: str
    required: true
  severity:
    description:
      - Update the severity level of the episode.
      - Common values are 1 (Info), 2 (Normal), 3 (Low), 4 (Medium), 5 (High), 6 (Critical).
    type: str
    required: false
  status:
    description:
      - Update the status of the episode.
      - Common values are 1 (New), 2 (In Progress), 3 (Pending), 4 (Resolved), 5 (Closed).
    type: str
    required: false
  owner:
    description:
      - Update the owner/assignee of the episode.
      - Can be a username or 'unassigned' to clear assignment.
    type: str
    required: false
  instruction:
    description:
      - Update the instruction field of the episode.
      - Contains guidance or notes about how to handle the episode.
    type: str
    required: false
  fields:
    description:
      - Dictionary of additional fields to update.
      - Allows updating any valid episode field not covered by specific parameters.
      - Field names should match ITSI episode schema.
    type: dict
    required: false

requirements:
  - Connection configuration requires C(ansible_connection=httpapi) and C(ansible_network_os=splunk.itsi.itsi_api_client).
  - Authentication via Bearer token, session key, or username/password as documented in the httpapi plugin.
notes:
  - This module updates existing ITSI episodes using the event_management_interface/notable_event_group endpoint.
  - Uses partial data updates (is_partial_data=1) to modify only specified fields.
  - The episode must exist before updating it.
  - Use notable_event_group_info module to retrieve episode IDs and current field values.
  - At least one field parameter (severity, status, owner, instruction, or fields) must be provided.
"""

EXAMPLES = r"""
# Update episode severity
- name: Set episode to critical severity
  splunk.itsi.update_episode_details:
    episode_id: "ff942149-4e70-42ff-94d3-6fdf5c5f95f3"
    severity: "6"

# Update episode status and owner
- name: Assign episode and mark in progress
  splunk.itsi.update_episode_details:
    episode_id: "ff942149-4e70-42ff-94d3-6fdf5c5f95f3"
    status: "2"
    owner: "admin"

# Update multiple fields at once
- name: Update episode with multiple fields
  splunk.itsi.update_episode_details:
    episode_id: "{{ episode_id }}"
    severity: "4"
    status: "2"
    owner: "incident_team"
    instruction: "Check database performance and disk space"

# Update using fields dictionary for custom fields
- name: Update custom episode fields
  splunk.itsi.update_episode_details:
    episode_id: "ff942149-4e70-42ff-94d3-6fdf5c5f95f3"
    fields:
      custom_field: "custom_value"
      priority: "high"
      
# Close an episode (status 5 = Closed)
- name: Close resolved episode
  splunk.itsi.update_episode_details:
    episode_id: "{{ target_episode_id }}"
    status: "5"
    instruction: "Issue resolved - monitoring system restored"

# Update episode from previous task result
- name: Get episodes and update first one
  block:
    - name: Get episode list
      splunk.itsi.notable_event_group_info:
        filter_data: '{"status": "1"}'
        limit: 1
      register: episodes_result
    
    - name: Update first new episode
      splunk.itsi.update_episode_details:
        episode_id: "{{ episodes_result.body.entry[0]._key }}"
        status: "2"
        owner: "analyst"
      when: episodes_result.body.entry | length > 0

# Error handling with status checking
- name: Update episode with error handling
  splunk.itsi.update_episode_details:
    episode_id: "{{ target_episode_id }}"
    severity: "3"
    status: "4"
  register: update_result
  failed_when: update_result.status != 200

- name: Show update result
  debug:
    msg: "Episode updated successfully with status {{ update_result.status }}"
  when: update_result.status == 200
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
  description: Response body from the ITSI API containing the updated episode key
  returned: always
  type: str
  sample: '{"_key": "ff942149-4e70-42ff-94d3-6fdf5c5f95f3"}'
update_data:
  description: The field data that was sent to the API for update
  returned: always
  type: dict
  sample:
    severity: "6"
    status: "2"
    owner: "admin"
episode_id:
  description: The episode ID that was updated
  returned: always
  type: str
  sample: "ff942149-4e70-42ff-94d3-6fdf5c5f95f3"
"""

import json

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.connection import Connection


def update_episode_details(conn, episode_id, update_data):
    """Update specific fields of an ITSI episode.
    
    Args:
        conn: Connection object from AnsibleModule
        episode_id: Episode ID (_key) to update
        update_data: Dictionary of fields to update
        
    Returns:
        tuple: (status_code, result_dict)
    """
    # Build the API path with episode ID and partial data parameter
    path = f"/servicesNS/nobody/SA-ITOA/event_management_interface/notable_event_group/{episode_id}/?is_partial_data=1"
    
    # Convert update data to JSON for the request body
    json_data = json.dumps(update_data)
    
    # Make POST request to update episode fields
    response = conn.send_request(path, method="POST", body=json_data)
    
    # Return status and response data
    return response["status"], response


def main():
    """Main module execution."""
    # Define module arguments
    module_args = dict(
        episode_id=dict(type='str', required=True),
        severity=dict(type='str', required=False),
        status=dict(type='str', required=False),
        owner=dict(type='str', required=False),
        instruction=dict(type='str', required=False),
        fields=dict(type='dict', required=False),
    )

    # Create AnsibleModule instance
    module = AnsibleModule(
        argument_spec=module_args,
        supports_check_mode=False
    )

    # Initialize update_data for error handling
    update_data = {}

    try:
        # Get connection to httpapi plugin
        conn = Connection(module._socket_path)
        
        # Extract parameters
        episode_id = module.params['episode_id']
        severity = module.params.get('severity')
        status = module.params.get('status')
        owner = module.params.get('owner')
        instruction = module.params.get('instruction')
        additional_fields = module.params.get('fields', {})
        
        # Build update data from provided parameters
        update_data = {}
        
        if severity is not None:
            update_data['severity'] = severity
        if status is not None:
            update_data['status'] = status
        if owner is not None:
            update_data['owner'] = owner
        if instruction is not None:
            update_data['instruction'] = instruction
            
        # Add any additional fields from the fields parameter
        if additional_fields:
            update_data.update(additional_fields)
        
        # Validate that at least one field is provided for update
        if not update_data:
            module.fail_json(
                msg="At least one field must be provided for update (severity, status, owner, instruction, or fields)"
            )
        # Update episode details
        status_code, result = update_episode_details(conn, episode_id, update_data)
        
        if status_code == 200:
            module.exit_json(
                changed=True,
                status=result["status"],
                headers=result["headers"],
                body=result["body"],
                update_data=update_data,
                episode_id=episode_id
            )
        else:
            module.fail_json(
                msg=f"Failed to update episode. HTTP status: {status_code}",
                status=status_code,
                headers=result.get("headers", {}),
                body=result.get("body", ""),
                update_data=update_data,
                episode_id=episode_id
            )
    
    except Exception as e:
        module.fail_json(
            msg=f"Exception occurred while updating episode: {str(e)}",
            episode_id=module.params.get('episode_id', 'unknown'),
            update_data=update_data
        )


if __name__ == '__main__':
    main()