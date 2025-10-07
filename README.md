# Splunk ITSI Ansible Collection

An official Ansible collection for automating **Splunk IT Service Intelligence (ITSI)** operations. This collection provides modules, plugins, and roles to manage ITSI services, episodes, correlation searches, aggregation policies, and more through Ansible automation.

## Features

### **ITSI Episodes Management**
- **List and filter episodes** using comprehensive search criteria
- **Update episodes** including severity, status, owner, and custom fields
- **Add comments** to episodes for collaboration and tracking
- **Event-Driven Ansible (EDA)** support for automated episode monitoring

### **ITSI Configuration Management**
- **Service management** - CRUD on ITSI services
- **Correlation searches** - Configure and manage correlation search rules
- **Aggregation policies** - Define and maintain aggregation policies

### **Connectivity & Integration**
- **HttpAPI plugin** for secure communication with Splunk ITSI
- **Multiple authentication methods** - Bearer tokens, session keys, username/password
- **Support for both core and netcommon httpapi** Ansible connections
- **SSL/TLS support** with certificate validation options

<!--start requires_ansible-->
**Ansible version compatibility:** This collection requires Ansible Core 2.14 or later.
<!--end requires_ansible-->

## External requirements

- **Splunk Enterprise** 8.0+ with **ITSI** 4.11+ installed
- **Python 3.8+** on the Ansible control node
- **Network connectivity** to your Splunk ITSI instance on the management port (8089/TCP by default)
- **Valid Splunk REST API credentials** with appropriate permissions for the operations you want to perform

## Included content

<!--start collection content-->
### Modules
- `splunk.itsi.notable_event_group_info` - Retrieve ITSI episode information
- `splunk.itsi.update_episode_details` - Update episode fields (severity, status, owner, etc.)
- `splunk.itsi.add_episode_comments` - Add comments to episodes
- `splunk.itsi.itsi_service` - Manage ITSI services
- `splunk.itsi.itsi_service_info` - Retrieve ITSI service information
- `splunk.itsi.itsi_correlation_search` - Manage correlation searches
- `splunk.itsi.itsi_aggregation_policy` - Manage aggregation policies

### Plugins
- `splunk.itsi.itsi_api_client` - HttpAPI plugin for ITSI API communication

### Roles
- `splunk.itsi.itsi_read_episodes` - Role for episode retrieval operations
- `splunk.itsi.run` - General-purpose execution role

### EDA (Event-Driven Ansible)
- `itsi_poll_episodes.yml` - Rulebook for automated episode monitoring
- `simple_test.yml` - Basic EDA testing rulebook
<!--end collection content-->

## Installation

### Install from Ansible Galaxy
```bash
ansible-galaxy collection install splunk.itsi
```

### Install from requirements.yml
```yaml
collections:
  - name: splunk.itsi
    version: ">=1.0.0"
```

```bash
ansible-galaxy collection install -r requirements.yml
```

### Install specific version
```bash
ansible-galaxy collection install splunk.itsi:==1.0.0
```

## Quick Start

### 1. Configure Connection
Create an inventory file with your Splunk ITSI instance:

```ini
[splunk]
your-splunk-instance.example.com

[splunk:vars]
ansible_connection=httpapi
ansible_network_os=splunk.itsi.itsi_api_client
ansible_httpapi_use_ssl=true
ansible_httpapi_port=8089
ansible_httpapi_validate_certs=false

# Choose one authentication method:
ansible_httpapi_token=YOUR_BEARER_TOKEN_HERE
# OR
ansible_user=admin
ansible_httpapi_pass=your-password
```

### 2. Basic Episode Management
```yaml
---
- name: Manage ITSI Episodes
  hosts: splunk
  gather_facts: false
  tasks:
    - name: Get critical episodes
      splunk.itsi.notable_event_group_info:
        filter_data: '{"severity": "6"}'
        limit: 10
      register: critical_episodes

    - name: Update episode status
      splunk.itsi.update_episode_details:
        episode_id: "{{ item._key }}"
        status: "2"  # In Progress
        owner: "incident_team"
      loop: "{{ critical_episodes.episodes }}"
      when: critical_episodes.episodes | length > 0

    - name: Add investigation comment
      splunk.itsi.add_episode_comments:
        episode_id: "{{ critical_episodes.episodes[0]._key }}"
        comment: "Investigation started by Ansible automation"
      when: critical_episodes.episodes | length > 0
```

### 3. Event-Driven Automation
Use EDA for automated episode monitoring:

```yaml
# rulebook.yml
---
- name: Monitor ITSI Episodes
  hosts: all
  sources:
    - ansible.eda.range:
        limit: 5
        delay: 30
  rules:
    - name: Check for critical episodes
      condition: event.i is defined
      action:
        run_playbook:
          name: handle_critical_episodes.yml
```

### 4. Service Management
```yaml
- name: Manage ITSI Services
  hosts: splunk
  tasks:
    - name: Get service information
      splunk.itsi.itsi_service_info:
        service_id: "web_service_01"
      register: service_info

    - name: Update service configuration
      splunk.itsi.itsi_service:
        name: "Web Service"
        description: "Updated via Ansible"
        state: present
```

See the `examples/` directory for more comprehensive playbooks and use cases.

## Release notes

See the
[changelog](https://github.com/ansible-collections/splunk.itsi/tree/main/CHANGELOG.rst).

## Authentication Methods

The collection supports multiple authentication methods:

### Bearer Token (Recommended)
```ini
ansible_httpapi_token=YOUR_BEARER_TOKEN_HERE
```

### Session Key
```ini
ansible_httpapi_session_key=YOUR_SESSION_KEY_HERE
```

### Username/Password
```ini
ansible_user=admin
ansible_httpapi_pass=your-password
```

## Connection Types

### Core HttpAPI
Uses Ansible's built-in httpapi connection:
```ini
ansible_connection=httpapi
ansible_network_os=splunk.itsi.itsi_api_client
```

### NetCommon HttpAPI (Advanced)
Provides additional timeout and HTTP client settings:
```ini
ansible_connection=ansible.netcommon.httpapi
ansible_network_os=splunk.itsi.itsi_api_client
ansible_command_timeout=60
ansible_httpapi_use_proxy=true
```

## Troubleshooting

### Common Issues

**Connection timeout:**
```ini
ansible_command_timeout=60
ansible_connect_timeout=30
```

**SSL certificate issues:**
```ini
ansible_httpapi_validate_certs=false
```

**Debug logging:**
```ini
ansible_persistent_log_messages=true
```

## Roadmap

- **v1.1.0**: Enhanced service management with KPI support

## Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING) for guidelines.

## More information

### Splunk ITSI Resources
- [Splunk ITSI Documentation](https://docs.splunk.com/Documentation/ITSI)
- [ITSI REST API Reference](https://docs.splunk.com/Documentation/ITSI/latest/RESTAPI)

### Ansible Resources
- [Ansible collection development forum](https://forum.ansible.com/c/project/collection-development/27)
- [Ansible User guide](https://docs.ansible.com/ansible/latest/user_guide/index.html)
- [Ansible Developer guide](https://docs.ansible.com/ansible/latest/dev_guide/index.html)
- [Event-Driven Ansible](https://www.ansible.com/products/event-driven-ansible)

### Community
- [Ansible Community code of conduct](https://docs.ansible.com/ansible/devel/community/code_of_conduct.html)
- [The Bullhorn (Ansible newsletter)](https://docs.ansible.com/ansible/devel/community/communication.html#the-bullhorn)

## Licensing

GNU General Public License v3.0 or later.

See [LICENSE](https://www.gnu.org/licenses/gpl-3.0.txt) to see the full text.
