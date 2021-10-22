# netslackbot

Uses the Nmap Python library to scan the local network, enumerate select systems and devices, attempts to login with default or known credentials, and sends a Slack message if it finds anything

# Requirements
* paramiko
* requests
* python-nmap

```
pip install -r requirements.txt
```

# Usage

```
python netslackbot.py
```