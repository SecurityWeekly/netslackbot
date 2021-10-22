import nmap
import socket
import sys
import requests
import paramiko
from paramiko.ssh_exception import AuthenticationException
from requests.auth import HTTPBasicAuth
from requests.auth import HTTPDigestAuth
from paramiko import SSHClient

#
# Try to login to the web interface using Basic and Digest Auth
#
def http_request(default_login, default_pw, url_location, ip):
    auth_methods = [HTTPBasicAuth, HTTPDigestAuth]
    # try Basic and Digest auth methods, if auth success then print auth_method success
    for auth_method in auth_methods:
        try:
            response = requests.get(f'http://{ip}{url_location}',
                                    auth=auth_method(default_login, default_pw),
                                    verify=False, timeout=2.0)

            if response.ok:
                return (str(auth_method)[22:][:-2] + ' success')
        except requests.exceptions.RequestException as e:
            pass

    return ''


#
# Try to login to the SSH service for a given host
#
def ssh_login(target_ip, target_port, ssh_username, ssh_password):
    ssh_client = SSHClient()
    ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy)

    try:
        ssh_client.connect(target_ip, port=target_port, username=ssh_username, password=ssh_password)
    except AuthenticationException as e:
        ssh_client.close()
        return ''
    else:
        ssh_client.close()
        return 'Successful login to ' + target_ip + 'on port: ' + str(target_port) + ' with: ' + ssh_username + ' : ' + ssh_password


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
def network_scan():
    print('Scanning network...')

    # assign interface_ip to get_ip_address return value
    interface_ip = get_ip_address()
    # Convert networkIP to 0/24 subnet ip range
    network_cidr = interface_ip[:interface_ip.rfind('.') + 1] + '0/24'
    # tcp ports to scan for found vendor device
    port_list = '21,22,23,80,81,8080'

    try:
        nm = nmap.PortScanner()  # instantiate nmap.PortScanner object
    except nmap.PortScannerError:
        print('Nmap not found', sys.exc_info()[0])
        sys.exit(1)
    except Exception as e:
        print("Unexpected error:", sys.exc_info()[0])
        sys.exit(1)

    # scan network with specified network_cidr and port_list
    nm.scan(network_cidr, port_list, arguments='-sS -O -T4', sudo=True)

    host_list = []

    for host in nm.all_hosts():

        host_entry = {'IP': '',
                      'Hostname': '',
                      'Vendor': '',
                      'Ports': [],
                      'Vulns': []}

        ip = str(nm[host]['addresses'])[10:-30]
        host_entry['IP'] = ip

        host_entry['Hostname'] = nm[host].hostname()

        if 'mac' in nm[host]['addresses']:
            vendor = ''
            # Try to scrape the full vendor name from the MAC association
            vendor = str(nm[host]['vendor'])[23:][:-2]

            # If that doesn't work, pull the vendor from OS fingerprinting
            if len(vendor) == 0:
                if 'osmatch' in nm[host]:
                    for osmatch in nm[host]['osmatch']:
                        if 'osclass' in osmatch:
                            for osclass in osmatch['osclass']:
                                vendor = osclass['vendor']
                                # Take the first vendor in the list...
                                break

            host_entry['Vendor'] = vendor

            # save only open ports
            for proto in nm[host].all_protocols():
                ports = nm[host][proto].keys()
                for port in ports:
                    port_state = nm[host][proto][port]['state']
                    # only print result for open ports
                    if 'open' in port_state:
                        host_entry['Ports'].append(str(port))

            vendor_list = ['Mobotix AG', 'Hangzhou Hikvision Digital Technology', 'Axis Communications AB',
                           'Zhejiang Dahua Technology', 'Panasonic Communications Co', 'Eaton', 'Raspberry Pi', 'Cisco Systems']

            # Match the vendors with the results and try to login, saving the results to the vulns field
            for vendor_string in vendor_list:
                if vendor_string in vendor:
                    # call http_request function if device vendor name contains target vendor
                    if 'Mobotix AG' in vendor_string:
                        # Mobotix: Default - admin/meinsm
                        host_entry['Vulns'] = http_request('admin', 'meinsm', '/control/userimage.html', ip)

                    elif 'Hangzhou Hikvision Digital Technology' in vendor_string:
                        # Hikvision: Firmware 5.3.0 and up requires unique password creation; previously admin/12345
                        host_entry['Vulns'] = http_request('admin', '12345', '/ISAPI/System/status', ip)

                    elif 'Axis Communications AB' in vendor_string:
                        # Axis: Traditionally root/pass, new Axis cameras require password creation during first login
                        host_entry['Vulns'] = http_request('root', 'pass',
                                     '/axis-cgi/admin/param.cgi?action=list&group=RemoteService', ip)

                    elif 'Zhejiang Dahua Technology' in vendor_string:
                        # Dahua: Requires password creation on first login, older models default to admin/admin
                        host_entry['Vulns'] = http_request('admin', 'admin',
                                     '/axis-cgi/admin/param.cgi?action=list&group=RemoteService', ip)

                    elif 'Panasonic Communications Co' in vendor_string:
                        # Panasonic TV default user: dispadmin/@Panasonic
                        host_entry['Vulns'] = http_request('dispadmin', '@Panasonic', '/cgi-bin/main.cgi', ip)

                    elif 'Eaton' in vendor_string:
                        # Eaton UPS default user: admin/admin
                        host_entry['Vulns'] = http_request('admin', 'admin', '/set_net.htm', ip)

                    elif 'Cisco' in vendor_string:
                        host_entry['Vulns'] = http_request('admin', 'cisco', '/', ip)

                    elif 'Raspberry Pi' in vendor_string:
                        host_entry['Vulns'] = ssh_login(ip, 22, 'pi', 'raspberry')

                    elif 'Ubiquiti' in vendor_string:
                        host_entry['Vulns'] = ssh_login(ip, 22, 'ubnt', 'ubnt')

                    else:
                        generic_login_test = None
                        generic_login_test = http_request('admin', 'admin', '/', ip)
                        if generic_login_test is not None:
                            host_entry['Vulns'] = generic_login_test

        else:
            host_entry['Vendor'] = 'No MAC Address'

        host_list.append(host_entry)

    print('Scanning finished.')
    return host_list
