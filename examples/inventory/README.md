# Inventory Files

This directory contains example inventory files for connecting to Splunk ITSI instances.

## Files

### Template Files (for reference)
- `hosts.ini` - Basic httpapi connection template
- `hosts_both.ini` - Template showing both core and netcommon httpapi methods
- `hosts_netcommon.ini` - NetCommon httpapi connection template with advanced features

## Setup for Development

1. Copy a template file to create your local version:
   ```bash
   cp hosts.ini hosts.local
   ```

2. Edit your `*.local` file with your actual Splunk instance details:
   - Replace `your-splunk-instance.example.com` with your Splunk server hostname/IP
   - Replace `YOUR_BEARER_TOKEN_HERE` with your actual bearer token
   - Replace `your-username` and `your-password` with your credentials

3. Use your local file in playbooks:
   ```bash
   ansible-playbook -i examples/inventory/hosts.local your-playbook.yml
   ```

## Authentication Methods

Choose **one** authentication method:

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

### Core HttpApi (`hosts.ini`)
- Uses Ansible's built-in httpapi connection
- Suitable for basic operations

### NetCommon HttpApi (`hosts_netcommon.ini`)
- Uses `ansible.netcommon.httpapi` for advanced features
- Provides additional timeout and HTTP client settings
- Better for complex automation scenarios

### Both (`hosts_both.ini`)
- Demonstrates both connection methods in one inventory
- Useful for testing and comparison