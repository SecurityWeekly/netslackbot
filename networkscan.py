import nmap
import socket
import sys
import requests
import paramiko
import toml
import os
import telnetlib
from paramiko.ssh_exception import AuthenticationException
from requests.auth import HTTPBasicAuth
from requests.auth import HTTPDigestAuth
from paramiko import SSHClient

import config


#
# Check to see if a file exists on the file system
#
def filesyscheck(path):
    if os.path.exists(path):
        #print("The file: "+path+" exists!")
        return True
    else:
        print("ERROR: The file: "+path+" does not exist!")
        return False


#
# Load credentials from configuration file
#
def load_creds(config_file, protocol):
    creds = []
    #
    # Read config values from the config.toml file
    # If one was not specified by the user, look for a config.toml file in the same directory
    #
    if config_file is not None:
        if filesyscheck(config_file):
            if config.DEBUG: print('INFO: Attempting to use user supplied config file: '+config_file)
            try:
                credsdb = toml.load(config_file)
            except Exception as e:
                print("ERROR: Unable to read creds config file: " + str(e))
                raise e
        else:
            raise Exception('ERROR: User specified config file not found')
    else:
        if filesyscheck("creds.toml"):
            if config.DEBUG: print('INFO: Attempting to use the default config file')
            credsdb = toml.load("creds.toml")
        else:
            raise Exception('ERROR: Config file creds.toml could be not found in current directory.')

    if protocol is not None:

        if protocol == 'http':
            for cred in credsdb['http']:
                for vendor in cred['vendors']:
                    credentials = {'vendor': vendor['name'], 'auth_type': vendor['auth_type'],
                                   'login_url': vendor['login_url'], 'creds': []}
                    for userpass in vendor['creds']:
                        credentials['creds'].append({'user': userpass['username'], 'pass': userpass['password']})

                    creds.append(credentials)
        elif protocol == 'ssh':
            for cred in credsdb['ssh']:
                for vendor in cred['vendors']:
                    credentials = {'vendor': vendor['name'], 'auth_type': vendor['auth_type'],
                                   'creds': []}
                    for userpass in vendor['creds']:
                        credentials['creds'].append({'user': userpass['username'], 'pass': userpass['password']})

                    creds.append(credentials)

        elif protocol == 'telnet':
            for cred in credsdb['telnet']:
                for vendor in cred['vendors']:
                    credentials = {'vendor': vendor['name'], 'auth_type': vendor['auth_type'],
                                   'creds': []}
                    for userpass in vendor['creds']:
                        credentials['creds'].append({'user': userpass['username'], 'pass': userpass['password']})

                    creds.append(credentials)

    return creds


#
# Try to login to the web interface using Basic and Digest Auth
#
def http_request(default_login, default_pw, url_location, ip, port):
    auth_methods = [HTTPBasicAuth, HTTPDigestAuth]
    # try Basic and Digest auth methods, if auth success then print auth_method success
    for auth_method in auth_methods:
        try:
            response = requests.get(f'http://{ip}:{port}{url_location}',
                                    auth=auth_method(default_login, default_pw),
                                    verify=False, timeout=2.0)

            if response.ok:
                return True
        except requests.exceptions.RequestException as e:
            pass

    return False


#
# Try to login to the SSH service for a given host
#
def ssh_login(target_ip, target_port, ssh_username, ssh_password):
    ssh_client = SSHClient()
    ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy)

    try:
        ssh_client.connect(target_ip,
                           port=target_port,
                           username=ssh_username,
                           password=ssh_password,
                           timeout=5,
                           allow_agent=False) # disable connecting to the SSH agent
    except AuthenticationException as e:
        if config.DEBUG: print('ERROR: SSH Authentication failed.')
        ssh_client.close()
        return False
    except Exception as oe:
        if config.DEBUG: print('ERROR: SSH failed: '+str(oe))
        ssh_client.close()
        return False
    else:
        ssh_client.close()
        return True


#
# Try to login to the TELNET service for a given host
#
def telnet_login(target_ip, target_port, telnet_username, telnet_password):
    timeout = 5
    t = telnetlib.Telnet(target_ip, port=target_port)  # actively connects to a telnet server
    #if config.DEBUG: t.set_debuglevel(1)                     # uncomment to get debug messages
    t.read_until(b'Username:', timeout=timeout)  # waits until it recieves a string 'login:'
    t.write(telnet_username.encode('utf-8'))  # sends username to the server
    t.write(b'\r')  # sends return character to the server
    t.read_until(b'Password:', timeout=timeout)  # waits until it recieves a string 'Password:'
    t.write(telnet_password.encode('utf-8'))  # sends password to the server
    t.write(b'\r')  # sends return character to the server
    n, match, previous_text = t.expect([br'Authentication failed', br'\$'], 10)
    if n == 0:
        print('TELNET Username and password failed - giving up')
        t.close()
        return False
    else:
        t.write(b'show ver\r')  # sends a command to the server
        t.write(b'\r')  # sends a command to the server
        #print(t.read_all().decode('utf-8'))  # read until socket closes
        print(t.read_very_eager().decode('utf-8'))  # read until socket closes
        t.close()
        return True


#
# Get the current interface IP address
#
def get_ip_address():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    return s.getsockname()[0]


#
# Scan the network, then match vendors and test for specific credentials
#
def network_scan(network_cidr, port_list, config_file):

    if not network_cidr:
        # assign interface_ip to get_ip_address return value
        interface_ip = get_ip_address()
        # Convert networkIP to 0/24 subnet ip range
        network_cidr = interface_ip[:interface_ip.rfind('.') + 1] + '0/24'

    # tcp ports to scan for found vendor device
    if port_list is None:
        port_list = '22,23,80,8080'

    try:
        nm = nmap.PortScanner()  # instantiate nmap.PortScanner object
    except nmap.PortScannerError:
        print('Nmap not found', sys.exc_info()[0])
        sys.exit(1)
    except Exception as e:
        print("Unexpected error:", sys.exc_info()[0])
        sys.exit(1)

    #
    # Load the credential databases:
    #
    try:
        http_creddb = load_creds(config_file, 'http')
        ssh_creddb = load_creds(config_file, 'ssh')
        telnet_creddb = load_creds(config_file, 'telnet')
    except Exception as e:
        sys.exit(1)

    print('Scanning network...')

    try:
        # scan network with specified network_cidr and port_list
        nm.scan(network_cidr, port_list, arguments='-sV -O -T4', sudo=True)
    except nmap.PortScannerError:
        print('Nmap port scan error', sys.exc_info()[0])
        sys.exit(1)
    except Exception as e:
        print("Unexpected error:", sys.exc_info()[0])
        sys.exit(1)

    host_list = []

    for host in nm.all_hosts():

        host_entry = {'IP': '',
                      'Hostname': '',
                      'Vendor': '',
                      'Ports': [],
                      'Vulns': []}

        if 'ipv4' in nm[host]['addresses']:
            ip = nm[host]['addresses']['ipv4']
        else:
            ip = str(nm[host]['addresses'])[10:-30]

        host_entry['IP'] = ip
        host_entry['Hostname'] = nm[host].hostname()
        vendor = ''

        # Try to scrape the full vendor name from the MAC association
        if 'mac' in nm[host]['addresses']:
            vendor = str(nm[host]['vendor'])[23:][:-2]

        # If that doesn't work, pull the vendor from OS fingerprinting
        if len(vendor) == 0:
            if 'osmatch' in nm[host]:
                for osmatch in nm[host]['osmatch']:
                    if 'osclass' in osmatch:
                        for osclass in osmatch['osclass']:
                            vendor += osclass['vendor']

        if len(vendor) > 0:
            host_entry['Vendor'] = vendor
        else:
            host_entry['Vendor'] = 'Not found.'

        # save only open ports
        for proto in nm[host].all_protocols():
            ports = nm[host][proto].keys()
            for port in ports:
                port_state = nm[host][proto][port]['state']
                port_service = nm[host][proto][port]['name']
                # only print result for open ports
                if 'open' in port_state:
                    host_entry['Ports'].append(str(port))
                    if config.DEBUG: print('Added open port: '+str(port)+' to host: '+ip+' running service: '+port_service)

                    if 'http' in port_service:
                        for cred_entry in http_creddb:
                            if cred_entry['vendor'] in vendor:
                                for userpass in cred_entry['creds']:
                                    if config.DEBUG: print('Trying '+userpass['user'] + " : " +userpass['pass'] + ' at URL: ' + cred_entry['login_url'] + ' for: ' + vendor + ' on port '+str(port))
                                    http_result = http_request(userpass['user'], userpass['pass'], cred_entry['login_url'], ip, port)
                                    if http_result:
                                        host_entry['Vulns'].append('Port: '+str(port)+' Successful Login using: '+userpass['user']+'/'+userpass['pass'])

                    elif 'ssh' in port_service:
                        for cred_entry in ssh_creddb:
                            if cred_entry['vendor'] in vendor:
                                for userpass in cred_entry['creds']:
                                    if config.DEBUG: print('Trying '+userpass['user'] + " : " +userpass['pass'] + ' for: ' + vendor + ' on port '+str(port))
                                    ssh_result = ssh_login(ip, port, userpass['user'], userpass['pass'])
                                    if ssh_result:
                                        host_entry['Vulns'].append('Port: '+str(port)+' Successful Login using: '+userpass['user']+'/'+userpass['pass'])
                            elif cred_entry['vendor'] == 'Default':
                                for userpass in cred_entry['creds']:
                                    if config.DEBUG: print('DEFAULTS: Trying '+userpass['user'] + " : " +userpass['pass'] + ' for: ' + vendor + ' on port '+str(port))
                                    ssh_result = ssh_login(ip, port, userpass['user'], userpass['pass'])
                                    if ssh_result:
                                        host_entry['Vulns'].append('Port: '+str(port)+' Successful Login using: '+userpass['user']+'/'+userpass['pass'])

                    elif 'telnet' in port_service:
                        for cred_entry in telnet_creddb:
                            if cred_entry['vendor'] in vendor:
                                for userpass in cred_entry['creds']:
                                    if config.DEBUG: print('Trying '+userpass['user'] + " : " +userpass['pass'] + ' for: ' + vendor + ' on port '+str(port))
                                    telnet_result = telnet_login(ip, port, userpass['user'], userpass['pass'])
                                    if telnet_result:
                                        host_entry['Vulns'].append('Port: '+str(port)+' Successful Login using: '+userpass['user']+'/'+userpass['pass'])

        host_list.append(host_entry)

    print('Scanning finished.')
    return host_list
