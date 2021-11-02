# Network Slack Bot

The purpose of this script is to scan the network via Nmap then, based on vendor, attempt to login with default credentials

## Installation & Usage

```
$ pip install -r requirements

$ python netslackbot.py
```

If you would like to scan an IP subnet outside the local range:

```
$ python3 netslackbot.py -t 192.168.1.0/24
```

Keep in mind that the manufacturer is derived from OS fingerprinting when scanning outside the local subnet range.

## Slack Variables

Make sure you create a "config.py" file that includes your Slack token and other info:
```
# config.py example

#
# Enter your Slack tokens and other parameters for your Slack channel here:
#
SLACK_TOKEN = ''
SLACK_CHANNEL = ''
SLACK_EMOJI = ''
SLACK_USERNAME = ''
```

## Configuration File: creds.toml

Currently SSH, HTTP and TELNET (Cisco only) are supported. You can define new vendors and protocols as follows:

```
#
# SSH default creds go here
#
# Name of the protocol goes first:
[[ssh]]

# Then you can define a vendor(s) as follows.
# Each vendor needs a name, this name has to match the vendor string found by nmap
# auth_type is not used, yet...
# Then define as many different creds as you like in the ssh.vendors.creds section
  [[ssh.vendors]]
    name = "Ubiquiti"
    auth_type = "userpass"

    [[ssh.vendors.creds]]
      username = "ubnt"
      password = "ubnt"
```

## Example Output

```{'IP': '192.168.0.25', 'Hostname': '', 'Vendor': 'Cisco Systems', 'Ports': ['22', '23', '80'], 'Vulns': ['Port: 23 Successful Login using: admin/admin', 'Port: 80 Successful Login using: admin/cisco', 'Port: 80 Successful Login using: admin/admin']}```