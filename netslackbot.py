import json
import argparse

# local imports
import slackbot
import networkscan


def get_args():
    # Assign description to the help doc
    parser = argparse.ArgumentParser(
        description='This script scans a network, finds devices and services with default creds and sends results to Slack')
    # Add arguments
    parser.add_argument(
        '-t', '--target', type=str, help='IP subnet range', required=False)
    # Array for all arguments passed to script
    args = parser.parse_args()
    # Assign args to variables
    ip_subnet = args.target
    # Return all variable values
    return ip_subnet


def main():
    #
    # Scan the network and save the results to a list
    #
    ip_subnet_range = get_args()
    host_results = networkscan.network_scan(ip_subnet_range)

    # Write the results to a file, send vulnerabilities to Slack
    with open('hosts.txt', 'w') as f:
        for host_entry in host_results:
            print(host_entry)
            f.write(json.dumps(host_entry))

            if len(host_entry['Vulns']) > 0:
                #print(json.dumps(host_entry['Vulns']))
                slackbot.post_message_to_slack(json.dumps(host_entry))


if __name__ == "__main__":
    main()