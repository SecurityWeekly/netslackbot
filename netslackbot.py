import json
import argparse

# local imports
import sys

import config
import slackbot
import networkscan


def get_args():
    # Assign description to the help doc
    parser = argparse.ArgumentParser(
        description='This script scans a network, finds devices and services with default creds and sends results to Slack')
    # Add arguments
    parser.add_argument(
        '-t', '--target', type=str, help='IP subnet range', required=False)
    parser.add_argument(
        '-c', '--config', type=str, help='Config file', required=False)
    parser.add_argument(
        '-p', '--ports', type=str, help='list of TCP ports, comma separated (Defaults: 22,23,80,8080)', required=False)
    # Array for all arguments passed to script
    args = parser.parse_args()
    # Assign args to variables
    ip_subnet = args.target
    config_file = args.config
    ports = args.ports
    # Return all variable values
    return ip_subnet, config_file, ports


def main():
    #
    # Scan the network and save the results to a list
    #
    ip_subnet_range, config_file, ports = get_args()
    host_results = networkscan.network_scan(ip_subnet_range, ports, config_file)

    # Write the results to a file, send vulnerabilities to Slack
    with open('hosts.txt', 'w') as f:
        for host_entry in host_results:
            if config.DEBUG: print(host_entry)
            f.write(json.dumps(host_entry))

            if len(host_entry['Vulns']) > 0:
                if config.DEBUG: print('Sending message to Slack: '+json.dumps(host_entry['Vulns']))
                try:
                    slackbot.post_message_to_slack(json.dumps(host_entry))
                except Exception as e:
                    print('ERROR: Unable to post Slack message: '+str(e))


if __name__ == "__main__":
    main()