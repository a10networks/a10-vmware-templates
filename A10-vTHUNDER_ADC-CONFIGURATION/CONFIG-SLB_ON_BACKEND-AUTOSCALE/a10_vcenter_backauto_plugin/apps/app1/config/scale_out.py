#!/backautovenv/bin/python3
"""
Script to scale out app server
"""
import os
import sys

sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))))

import ipaddress
import json
import random
import string
import time
import re
import paramiko
import requests
import socket
from collections import Counter

from plugins.thunder.thunder import ThunderManager
from plugins.vcenter.config_manager import ConfigManager
from plugins.vcenter.session_manager import SessionManager
from plugins.utils.virtual_machine import VirtualMachine
from plugins.utils.logger import logger

import warnings
warnings.filterwarnings('ignore')


class ScaleOutAppServer:
    def __init__(self, config, app_servers, vcenter_config, session_id):
        self.config = config
        self.app_servers = app_servers
        self.session_id = session_id
        self.vcenter_config = vcenter_config
        self.vcenter_ip = self.vcenter_config.get('vCenter Configs', 'vcenter_server_ip')
        self.base_url = "https://{}/api/vcenter/".format(self.vcenter_ip)

    def deploy_new_vm(self):
        """
            function to deploy a new virtual machine by cloning source machine
            :return:
        """
        # vcenter api to create a clone
        url = self.base_url + 'vm?action=clone'
        headers = {
            'Content-Type': 'application/json',
            'vmware-api-session-id': self.session_id
        }
        # generate vm name in format reference_server_name + random 6 char string
        server_name_prefix = self.config.get('App/Web Server Configs', 'source_vm_name')
        vm_name = server_name_prefix + '-' + ''.join(
            random.choices(string.ascii_uppercase + string.digits, k=6)
        )
        # payload
        body = json.dumps({
            "name": vm_name,
            "power_on": True,
            "source": self.config.get('App/Web Server Configs', 'clone_vm_id'),
            # "guest_customization_spec": {
            #     "name": self.config.get('App/Web Server Configs', 'source_customization_spec_name')
            # },
            "placement": {
                "cluster": self.config.get('vCenter Inventory', 'cluster_id'),
                "datastore": self.config.get('vCenter Inventory', 'datastore_id'),
                "folder": self.config.get('vCenter Inventory', 'folder_id')
            }
        })
        try:
            response = requests.request("POST", url, headers=headers, data=body, verify=False)
            if response.status_code == 200:
                return vm_name, response.text.replace('"', '')
            logger.error(eval(response.text)['messages'][0]['default_message'])
            return None, None
        except Exception as exp:
            logger.error(exp)
            return None,None

    def get_available_ip_addr(self):
        """
        function to get an available ip address from CIDR
        :return:
        """
        subnet = self.config.get('App/Web Server Configs', 'server_subnet')
        assigned_ips = self.app_servers.get('AppServer', 'assigned_ip_addr')

        ip_in_subnet = [str(ip) for ip in ipaddress.IPv4Network(subnet)]
        # remove x.1, x.2, x.3 and x.255 reserved ips from a subnet
        ip_in_subnet.pop(-1)
        ip_in_subnet.pop(0)
        ip_in_subnet.pop(0)
        ip_in_subnet.pop(0)
        # get random ip address from ip_in_subnet list
        ip_addr = ip_in_subnet[0]
        index = 1
        while ip_addr in assigned_ips:
            # check if all ips are assigned
            if ip_addr == ip_in_subnet[-1]:
                raise Exception("No ip address available for server in subnet %s" % subnet)
            # get next ip address in ip_in_subnet list
            ip_addr = ip_in_subnet[index]
            index += 1

        response = os.system("sudo ping -c 2 -W 2 " + ip_addr)
        #and then check the response...
        if response == 0:
            assigned_ips = eval(assigned_ips)
            assigned_ips.add(ip_addr)
            assigned_ips = str(assigned_ips)
            cfg.set_config(section='AppServer', key='assigned_ip_addr', value=assigned_ips)
            ip_addr = self.get_available_ip_addr()
        return ip_addr

    @staticmethod
    def ssh_connect(host, user, password):
        """
        function to create a ssh connection with server
        :return:
        """
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        max_wait_time_sec = 300
        current_time = 0
        attempt = 1
        while current_time <= max_wait_time_sec:
            try:
                ssh.connect(host, port=22, username=user, password=password)
            except Exception as exp:
                logger.warning("Failed to conn SSH for host %s" % host)
                logger.error(exp)
                time.sleep(30)
                current_time += 30
                logger.info("Retrying attempt %s" % attempt)
                attempt += 1
            else:
                logger.debug("ssh connection successful.")
                return ssh
        logger.error("SSH timeout after multiple attempts.")
        return None

    def assign_ip(self):
        """
        function to assign an available ip address from CIDR block to server vm.
        :return:
        """
        available_ip = self.get_available_ip_addr()
        subnet = self.config.get('App/Web Server Configs', 'server_subnet')
        subnet_mask = ipaddress.ip_interface(subnet).netmask
        user = self.config.get('App/Web Server Configs', 'source_vm_username')
        password = self.config.get('App/Web Server Configs', 'source_vm_password')
        host_ip = self.config.get('App/Web Server Configs', 'source_transit_ip')
        interface_name = self.config.get('App/Web Server Configs', 'source_interface_name')
        dns_server = self.config.get('App/Web Server Configs', 'source_dns')
        gateway = self.get_gateway(ip_address=available_ip, netmask=subnet_mask)
        prefix_length = self.netmask_to_prefix_length(netmask=str(subnet_mask))
        os_type = self.config.get('App/Web Server Configs', 'source_vm_os')
        new_ip = None
        if os_type.lower() == 'centos' or os_type.lower() == 'rhel':
            new_ip = self.change_ip_address_centos(hostname=host_ip, username=user, password=password,
                                          interface=interface_name,
                                          new_ip=available_ip,
                                          prefix_length=prefix_length,
                                          gateway=gateway,
                                          dns_server=dns_server)
        elif os_type.lower() == 'ubuntu':
            new_ip = self.change_ip_address_ubuntu(hostname=host_ip, username=user, password=password,
                                          interface=interface_name,
                                          new_ip=available_ip,
                                          netmask=prefix_length,
                                          gateway=gateway,
                                          dns_server=dns_server)
        else:
            new_ip = None
            raise Exception("source vm os must be centos or ubuntu.")

        if new_ip == None:
            return None
        assigned_ips = self.app_servers.get('AppServer', 'assigned_ip_addr')
        assigned_ips = eval(assigned_ips)
        assigned_ips.add(available_ip)
        assigned_ips = str(assigned_ips)
        cfg.set_config(section='AppServer', key='assigned_ip_addr', value=assigned_ips)
        return available_ip

    def remove_ip(self, assigned_ip):
        """
        function to remove deleted server assigned ip from config.ini
        :param assigned_ip:
        :return:
        """
        assigned_ips = self.app_servers.get('AppServer', 'assigned_ip_addr')
        assigned_ips = eval(assigned_ips)
        if assigned_ip in assigned_ips:
            assigned_ips.remove(assigned_ip)
            assigned_ips = str(assigned_ips)
            cfg.set_config(section='AppServer', key='assigned_ip_addr', value=assigned_ips)
    
    def change_ip_address_ubuntu(self, hostname, username, password, interface, new_ip, netmask, gateway, dns_server):
        try:
            retries = 0
            max_retries = 5
            retry_interval = 60
            while retries < max_retries:
                try:
                    # Create an SSH client
                    ssh = paramiko.SSHClient()
                    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

                    # Connect to the remote host
                    ssh.connect(hostname, username=username, password=password)

                    # Build the nmcli command to change the IP address
                    # nmcli_command = f"sudo nmcli connection modify '{interface}' ipv4.method manual ipv4.addresses {new_ip}/{netmask} ipv4.gateway {gateway} ipv4.dns {dns_server}"
                    nmcli_command = f"sudo nmcli connection modify '{interface}' ipv4.method manual ipv4.addresses {new_ip}/{netmask} ipv4.dns {dns_server}"

                    # Execute the nmcli command
                    stdin, stdout, stderr = ssh.exec_command(nmcli_command)

                    # Restart the network connection
                    restart_command = f"sudo nmcli connection down '{interface}' && sudo nmcli connection up '{interface}'"
                    stdin, stdout, stderr = ssh.exec_command(restart_command)
                    logger.info("Connection modified, Successfully assigned IP '%s' to VM." % new_ip)
                    return new_ip
                except paramiko.AuthenticationException as auth_exc:
                    logger.error(f"Authentication failed: {auth_exc}")
                    # break  # Authentication failure won't be retried
                    return None

                except Exception as e:
                    logger.error(f"Connection failed: {e}")
                    retries += 1
                    time.sleep(retry_interval)
        except Exception as e:
            logger.error(f"Error: {e}")
            return None
        finally:
            # Close the SSH connection
            ssh.close()

    def change_ip_address_centos(self, hostname, username, password, interface,
                                 new_ip, prefix_length, gateway, dns_server):
        """
        Change the IP address of a Linux VM using SSH.

        Parameters:
        - hostname: IP address or hostname of the Linux VM.
        - username: SSH username for connecting to the VM.
        - password: SSH password for connecting to the VM.
        - interface: Network interface name (e.g., 'eth0', 'ens33').
        - new_ip: New IP address to be set.
        - prefix_length: prefix_length for the new IP address.
        - gateway: Default gateway for the new IP address.
        - dns_server: Primary dns for the new IP address.
        """
        try:
            retries = 0
            max_retries = 5
            retry_interval = 60
            while retries < max_retries:
                try:
                    # Create an SSH client
                    ssh = paramiko.SSHClient()
                    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

                    # Attempt to connect
                    ssh.connect(hostname, username=username, password=password)

                    # Check if the connection exists
                    # if self.nmcli_connection_exists(ssh, interface):
                    # interface = 'System %s' % interface
                    ssh.exec_command(
                        f"sudo nmcli connection modify '{interface}' ipv4.addresses {new_ip}/{prefix_length} ipv4.gateway {gateway} ipv4.dns {dns_server}")
                    
                    # Restart the network connection
                    command = f"sudo nmcli connection down '{interface}' && sudo nmcli connection up '{interface}'"
                    stdin, stdout, stderr = ssh.exec_command(command)

                    logger.info("Connection modified, Successfully assigned IP '%s' to VM." % new_ip)
                    return new_ip
                except paramiko.AuthenticationException as auth_exc:
                    logger.error(f"Authentication failed: {auth_exc}")
                    # break  # Authentication failure won't be retried
                    return None

                except Exception as e:
                    logger.error(f"Connection failed: {e}")
                    retries += 1
                    time.sleep(retry_interval)
        except Exception as e:
            logger.error(f"Error: {e}")
            return None
        finally:
            # Close the SSH connection
            ssh.close()

    def netmask_to_prefix_length(self, netmask):
        """
        Convert netmask to prefix length in CIDR notation.

        Parameters:
        - netmask: Netmask in dotted decimal format (e.g., '255.255.255.0').

        Returns:
        - Prefix length in CIDR notation (e.g., '/24').
        """
        # Split the netmask into octets
        octets = [int(octet) for octet in netmask.split('.')]

        # Calculate the binary representation of the netmask
        binary_netmask = ''.join(format(octet, '08b') for octet in octets)

        # Count the number of consecutive '1' bits
        prefix_length = binary_netmask.count('1')

        return prefix_length

    def get_gateway(self, ip_address, netmask):
        """
        Get the gateway value for an IP address with a netmask.

        Parameters:
        - ip_address: IP address in dotted decimal format (e.g., '192.168.1.1').
        - netmask: Netmask in dotted decimal format (e.g., '255.255.255.0').

        Returns:
        - Gateway IP address.
        """
        network = ipaddress.IPv4Network(f"{ip_address}/{netmask}", strict=False)
        return str(network.network_address + 1)

    def nmcli_connection_exists(self, ssh, connection_name):
        """
        Check if a NetworkManager connection exists on the target machine.

        Parameters:
        - ssh: SSH client object.
        - connection_name: Name of the NetworkManager connection.

        Returns:
        - True if the connection exists, False otherwise.
        """
        try:
            # Run nmcli command on the target machine
            stdin, stdout, stderr = ssh.exec_command(f"nmcli connection show --active | grep '{connection_name}'")

            # Check if the connection name is found in the output
            return connection_name in stdout.read().decode("utf-8")

        except Exception as e:
            logger.error(f"Error checking connection existence: {e}")
            return False

    def is_service_running(self, server_ip, port):
        try:
            # Create a socket object
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

            # Set a timeout for the connection attempt
            sock.settimeout(2)  # Timeout in seconds

            # Attempt to connect to the server
            result = sock.connect_ex((server_ip, port))

            # Check if the connection was successful
            if result == 0:
                logger.debug(f"Service is running on {server_ip}:{port}")
                return True
            else:
                logger.debug(f"Service is not running on {server_ip}:{port}")
                return False
        except Exception as e:
            logger.error(f"Error while checking service status on VM: {e}")
            return False
        finally:
            # Close the socket
            sock.close()
    
    def poweroff_delete_vm_on_failure(self,vm_id):
        max_wait_time = 120
        current_time = 0
        while not vm.is_vm_powered_off(vm_id=vm_id):
            if current_time >= max_wait_time:
                raise Exception("Failed to power off vm %s." % vm_name)
            status = vm.power_off_vm(vm_id=vm_id)
            time.sleep(10)
            current_time += 10
        logger.info("Powered off vm %s." % vm_name)
        status = vm.delete_vm(vm_id=vm_id)
        if status == 204:
            logger.info('Successfully deleted vm {}.'.format(vm_name))
        else:
            logger.error('Failed to delete VM %s.' % vm_name)

    def get_transit_ip_using_interface_name(self,hostname,source_interface_name,source_user_name,source_user_password):
        try:
            retries = 0
            max_retries = 5
            retry_interval = 30
            while retries < max_retries:
                try:
                    # Create an SSH client
                    ssh = paramiko.SSHClient()
                    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

                    # Connect to the remote host
                    ssh.connect(hostname, username=source_user_name, password=source_user_password)

                    # Build the nmcli command to change the IP address
                    get_ip_command = f"ip addr show {source_interface_name}"

                    # Execute the nmcli command
                    stdin, stdout, stderr = ssh.exec_command(get_ip_command)
                    # return new_ip
                    ip_output = stdout.read().decode("utf-8")
                    print(ip_output)
                    ip_match = re.search(r'inet (\S+/\d+)', ip_output)
                    if ip_match:
                        ip_address_with_cidr = ip_match.group(1)
                        ip_address = ip_address_with_cidr.split('/')[0]
                        return ip_address
                    else:
                        return None
                except paramiko.AuthenticationException as auth_exc:
                     return "connection_error"
                except Exception as e:
                    retries +=1
                    logger.error("Unable to connect to VM %s. Retry - %s" % (hostname, retries))
                    time.sleep(retry_interval)
        except Exception as e:
            print(f"Error: {e}")
            return None
        finally:
            # Close the SSH connection
            ssh.close()

if __name__ == '__main__':
    try:
        start_time = time.time()
        logger.info("Scale out operation triggered.")
        session_id = ""
        app_name = os.path.basename(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        cfg = ConfigManager(app_name=app_name)
        configurations, app_servers, vcenter_config = cfg.get_configs()
        thunder_ip_addresses = configurations.get('Thunder Configs', 'thunder_ip')
        if ',' in thunder_ip_addresses:  
            thunder_ip_addresses = thunder_ip_addresses.replace(' ', '')
            thunder_ip_addresses = thunder_ip_addresses.split(',')
        if type(thunder_ip_addresses) != list:
            thunder_ip_addresses = [thunder_ip_addresses]
        
        duplicates = [item for item, count in Counter(thunder_ip_addresses).items() if count > 1]
        if duplicates:
            logger.warning("Duplicate vThunder IP addresses %s found in 'thunder_ip' in config.ini." % duplicates)
        thunder_ip_addresses = set(thunder_ip_addresses)
        cool_down = float(configurations.get('AutoScale Configs', 'cool_down'))
        last_scaling_timestamp = float(app_servers.get('AppServer', 'last_scaling_timestamp'))
        services_ports = configurations.get('App/Web Server Configs', 'services_ports')
        if ',' in services_ports:   
            services_ports = services_ports.replace(' ', '')
            services_ports = services_ports.split(',')
        if type(services_ports) != list:
            services_ports = [services_ports]
        services_ports = set(services_ports)
        
        current_timestamp = time.time()
        logger.debug('cool down time is %s' % (cool_down))
        logger.debug('time from last scaling operation is %s' % (current_timestamp - last_scaling_timestamp))
        if (current_timestamp - last_scaling_timestamp) < cool_down:
           logger.warning("Scale out operation failed because operation triggered within cool down period.")
           exit(0)
        if len(thunder_ip_addresses) < 1:
            logger.error("No 'thunder_ip' provided in config.ini")
            exit(0)
        cfg.set_config(section='AppServer',
                                key='last_scaling_timestamp',
                                value=str(current_timestamp))

        session = SessionManager(vcenter_config)
        session_id = session.get_session()
        vm = VirtualMachine(session_id=session_id, vcenter_config=vcenter_config)

        max_scale_out = eval(configurations.get('AutoScale Configs', 'maximum_replica'))
        folder = configurations.get('vCenter Inventory', 'folder_id')
        current_running_app_servers = len(vm.list_all_vms(folder=folder))
        if max_scale_out <= current_running_app_servers:
            logger.warning("Scale out operation failed because scale out capacity limit reached.")
            exit(0)

        scaleout = ScaleOutAppServer(config=configurations,
                                    app_servers=app_servers,
                                    vcenter_config=vcenter_config,
                                    session_id=session_id)

        vm_name, vm_id = scaleout.deploy_new_vm()
        if vm_name:
            # assign ip address to server vm
            source_transit_ip = configurations.get('App/Web Server Configs', 'source_transit_ip')
            source_interface_name = configurations.get('App/Web Server Configs', 'source_interface_name')
            source_user_name = configurations.get('App/Web Server Configs', 'source_vm_username')
            source_user_password = configurations.get('App/Web Server Configs', 'source_vm_password')
            result = scaleout.get_transit_ip_using_interface_name(source_transit_ip,source_interface_name,source_user_name,source_user_password)

            if result == "connection_error":
                logger.error("Scale out operation failed.[invalid username or password provided for source VM in config.ini].")
                scaleout.poweroff_delete_vm_on_failure(vm_id)
                exit(0)
            else:

                 if result !=source_transit_ip or result is None:
                    logger.error("Scale out operation failed. [Invalid value provided for 'source_interface_name' or 'source_transit_ip' in config.ini].")
                    scaleout.poweroff_delete_vm_on_failure(vm_id)
                    exit(0)

            assigned_ip = scaleout.assign_ip()
            if assigned_ip is None:
                scaleout.poweroff_delete_vm_on_failure(vm_id)
                scaleout.remove_ip(assigned_ip=assigned_ip)
                logger.error("Scale out operation failed, Unable to assign new IP %s to VM %s." % (assigned_ip, vm_name))
                exit(0)

            max_retry = int(configurations.get('App/Web Server Configs', 'service_up_timeout'))
            cur_retry = 0

            logger.debug("Waiting for the services to start on VM %s." % vm_name)
            for port in services_ports:
                port = int(port)
                while(True):
                    is_service_up = scaleout.is_service_running(server_ip=assigned_ip, port=port)
                    if(is_service_up):
                        break
                    if(max_retry < cur_retry):
                        logger.warning("The service is unable to start in req time on %s port in VM %s." % (port, vm_name))
                        #code to delete vm
                        scaleout.poweroff_delete_vm_on_failure(vm_id)
                        scaleout.remove_ip(assigned_ip=assigned_ip)
                        exit(0)
                    time.sleep(2)
                    cur_retry += 2
            
            server = {
                "name": vm_name,
                "ip_address": assigned_ip
            }
            # config new server information in Thunder devices
            is_server_configured = False
            thunder_username = configurations.get('Thunder Configs', 'thunder_username')
            thunder_password = configurations.get('Thunder Configs', 'thunder_password')
            for thunder_ip in thunder_ip_addresses:
                thunder = ThunderManager(mgmt_ip=thunder_ip,
                                        username=thunder_username,
                                        password=thunder_password,
                                        configurations=configurations)
                if thunder.authorization_token:
                    if thunder.is_partition_activated:
                        is_server_configured = thunder.config_server(server=server) or is_server_configured
                        thunder.write_memory()
                    thunder.logoff()
                
            if not is_server_configured:
                scaleout.poweroff_delete_vm_on_failure(vm_id)
                scaleout.remove_ip(assigned_ip=assigned_ip)
                
            logger.info("Finished scale out operation.")
        else:
            logger.info("VM not created.")
    except Exception as exp:
        logger.error(exp)
    finally:
        if session_id:
            session.delete_session(session_id=session_id)
        end_time = time.time()
        logger.info("Total time taken: %s seconds" % (end_time - start_time))
