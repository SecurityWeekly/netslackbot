import json

# local imports
import slackbot
import networkscan

def main():
    #
    # Scan the network and save the results to a list
    #
    host_results = networkscan.network_scan()

    # Write the results to a file, send vulnerabilities to Slack
    with open('hosts.txt', 'w') as f:
        for host_entry in host_results:
            print(host_entry)
            f.write(json.dumps(host_entry))

            if len(host_entry['Vulns']) > 0:
                #print(json.dumps(host_entry['Vulns']))
                slack.post_message_to_slack(json.dumps(host_entry))

if __name__ == "__main__":
    main()