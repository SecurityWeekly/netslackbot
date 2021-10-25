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