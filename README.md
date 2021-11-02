# Network Slack Bot

The purpose of this script is to scan the network via Nmap then, based on vendor, attempt to login with default credentials.
It collects the vendor name/type for each device that is discovered on the network. 
You can define vendors in each protocol section of the config file (currently only supports HTTP (Basic or Digest Auth), SSH, and TELNET (Cisco devices only)).
For each vendor, for a given protocol, you can define multiple username/password pairs to test.
All results are written to a local file and vulnerabilities are sent to a specified slack channel.

## Installation & Usage

```
$ pip install -r requirements

$ python netslackbot.py -h
usage: netslackbot.py [-h] [-t TARGET] [-c CONFIG] [-p PORTS]

This script scans a network, finds devices and services with default creds and sends results to Slack

optional arguments:
  -h, --help            show this help message and exit
  -t TARGET, --target TARGET
                        IP subnet range
  -c CONFIG, --config CONFIG
                        Config file
  -p PORTS, --ports PORTS
                        list of TCP ports, comma separated (Defaults: 22,23,80,8080)

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

# If you want a ton of debugging messages, set to True:
DEBUG = False
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