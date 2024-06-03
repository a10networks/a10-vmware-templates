"""
Script to upload source code into vCenter VM and grant vpxd service to read, write and execute permission.
"""
import ipaddress
import json
import time
import re
import os
from configobj import ConfigObj 
import paramiko
import requests
from requests.auth import HTTPBasicAuth
from scp import SCPClient

from a10_vcenter_backauto_plugin.plugins.utils.logger import logger

import warnings
warnings.filterwarnings('ignore')


class DeploymentManager:
    def __init__(self, vcenter_config, main_config):
        self.vcenter_config = vcenter_config
        self.main_config = main_config
        self.host = self.vcenter_config['vCenter Configs']['vcenter_server_ip']
        self.port = 22
        self.user = self.vcenter_config['vCenter Configs']['vcenter_server_ssh_username']
        self.password = self.vcenter_config['vCenter Configs']['vcenter_server_ssh_password']
        self.source_path = "a10_vcenter_backauto_plugin"
        self.remote_path = self.vcenter_config['vCenter Configs']['installation_dir']
        self.full_remote_path = '%s/%s'%(self.remote_path, 'a10_vcenter_backauto_plugin')
        self.vcenter_ui_username = self.vcenter_config['vCenter Configs']['vcenter_server_ui_username']
        self.vcenter_ui_password = self.vcenter_config['vCenter Configs']['vcenter_server_ui_password']
        self.base_url = "https://{}/api/vcenter/".format(self.host)
        self.session_id = self.create_session()

    def ssh_connect(self):
        """
        function to create a ssh connection with server
        :return:
        """
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        max_wait_time_sec = 120
        current_time = 0
        attempt = 1
        while current_time <= max_wait_time_sec:
            try:
                ssh.connect(self.host, port=22, username=self.user, password=self.password)               
            except Exception as exp:
                print("Failed to SSH vcenter VM %s" % self.host)
                logger.error(exp)
                time.sleep(30)
                current_time += 30
                logger.info("Retrying attempt %s" % attempt)
                attempt += 1
            else:
                logger.debug("SSH connection with vCenter VM successful.")
                return ssh
        logger.error("SSH timeout after multiple attempts.")
        return None

    def grant_access_permissions(self):
        print('Granting read, write and execute permissions...')
        ssh = self.ssh_connect()
        cmds = [
            "chown vpxd %s" % self.remote_path,
            "chown vpxd %s" % self.full_remote_path,
            "chown vpxd %s/*" % self.full_remote_path,
            "chown vpxd %s/apps/*" % self.full_remote_path,
            "chown vpxd %s/plugins/*" % self.full_remote_path,
            "chmod 744  %s/*.ini" % self.full_remote_path,
            "chmod 744  %s/*.txt" % self.full_remote_path,
            "chown vpxd %s/apps/app1/*" % self.full_remote_path,
            "chmod 744  %s/apps/app1/*.ini" % self.full_remote_path,
            "chown vpxd %s/apps/app1/config/*" % self.full_remote_path,
            "chown vpxd %s/apps/app1/logs/*" % self.full_remote_path,
            "chmod 744  %s/apps/app1/config/*.py" % self.full_remote_path,
            "chmod 744  %s/plugins/*.py" % self.full_remote_path,
            "chmod 744  %s/plugins/thunder/*.py" % self.full_remote_path,
            "chmod 744  %s/plugins/utils/*.py" % self.full_remote_path,
            "chmod 744  %s/plugins/vcenter/*.py" % self.full_remote_path,
        ]
        for cmd in cmds:
            ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command(cmd)
        ssh.close()
        print('Done.')

    def upload(self):
        """
        function to get source code from local and upload to remote vcenter VM.
        :return:
        """
        client = self.ssh_connect()
        if client == None:
            return
        client.connect(self.host, self.port, self.user, self.password)

        scp_client = SCPClient(client.get_transport())
        scp = client.open_sftp()
        print('Uploading package into vcenter...')
        scp_client.put(self.source_path, recursive=True, remote_path=self.remote_path)
        print('Uploaded.')
        scp.close()
        scp_client.close()
        client.close()
        logger.info("Uploaded source code into vCenter.")

    def check_vcenter_vm(self):
        """
        function to check if vcenter server can be connected and installation
        directory already exists.
        :return:
        """
        
        client = self.ssh_connect()
        if client == None:
            return False
        client.connect(self.host, self.port, self.user, self.password)
        scp_client = SCPClient(client.get_transport())
        scp = client.open_sftp()
        try:
            scp.stat(self.remote_path)
        except FileNotFoundError:
            print(f"Remote folder '{self.remote_path}' does not exist. Creating...")
            scp.mkdir(self.remote_path)
        try:
            scp.stat(self.full_remote_path)
            name = input("Directory '%s' already exists, this will overwrite files of directory.\nDo you want to proceed? [yes/no]:" % self.full_remote_path)
            if name.lower().strip() != "yes":
                print("Provide different 'installation_dir' path in vcenter.ini and rerun setup.py.")
                return False
        except FileNotFoundError:
            pass
        scp.close()
        scp_client.close()
        client.close()
        return True

    def setup_virtualenv(self):
        print('Setup virtual environment...')
        client = self.ssh_connect()
        cmds = [
            "pip3 install virtualenv",
            "virtualenv /backautovenv",
            "source /backautovenv/bin/activate && /backautovenv/bin/pip install -r %s/requirements.txt" % self.full_remote_path,
            "sed -i 's/\r$//' %s/apps/app1/config/scale_in.py" % self.full_remote_path,
            "sed -i 's/\r$//' %s/apps/app1/config/scale_out.py" % self.full_remote_path
        ]
        for cmd in cmds:
            ssh_stdin, ssh_stdout, ssh_stderr = client.exec_command(cmd)
            time.sleep(10)
        client.close()
        print('Done.')
        logger.info("Completed virtualenv setup in vCenter.")

    def clone_server(self):
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
        vm_name = self.main_config['App/Web Server Configs']['clone_vm_name']
        # payload
        body = json.dumps({
            "name": vm_name,
            "power_on": False,
            "source": self.main_config['App/Web Server Configs']['source_vm_id'],
            # "guest_customization_spec": {
            #     "name": self.main_config.['App/Web Server Configs', 'source_customization_spec_name')
            # },
            "placement": {
                "cluster": self.main_config['vCenter Inventory']['cluster_id'],
                "datastore": self.main_config['vCenter Inventory']['datastore_id'],
                "folder": self.main_config['vCenter Inventory']['folder_id']
            }
        })
        try:
            print('Cloning source vm...')
            response = requests.request("POST", url, headers=headers, data=body, verify=False)
            if response.status_code == 200:
                return response.text
            return None
        except Exception as exp:
            logger.error(exp)
            return None

    def create_session(self):
        """
            function to create vsphere vcenter session
            :return session_id:
            """
        url = "https://{}/api/".format(self.host) + 'session/'
        headers = {
            'Content-Type': 'application/json'
        }
        try:
            response = requests.request("POST", url, headers=headers,
                                        auth=HTTPBasicAuth(self.vcenter_ui_username,
                                                        self.vcenter_ui_password),
                                        verify=False)

            if response.status_code == 201:
                response = response.json()
                logger.info("Created session %s" % response)
                return response
            return None
        except Exception as exp:
            # logger.error(exp)
            return None

    def delete_session(self):
        """
        function to delete vsphere vcenter session
        :return status_code:
        """
        url = self.base_url + 'session'
        headers = {
            'vmware-api-session-id': self.session_id
        }
        response = requests.delete(url=url, headers=headers, verify=False)
        if response.status_code == 204:
            logger.info('Deleted session %s' % self.session_id)
        return response.status_code
    
    def validate_config(self, config, file_name):
        for section_name in config:
            # get each section values
            for key, value in config[section_name].items():
                # check null values
                if not value:
                    raise Exception("key %s value not found or empty, "
                                    "fill value in %s file" % (key, file_name))
    
    def is_valid_datastore_id(self, id):
        url = self.base_url + 'datastore/{}'.format(id)
        headers = {
            'vmware-api-session-id': self.session_id
        }
        try:
            response = requests.request("GET", url, headers=headers, verify=False)
            if response.status_code == 200:
                return response.text
        except Exception as exp:
            logger.error(exp)
            return None
    
    def is_valid_cluster_id(self, id):
        url = self.base_url + 'cluster/{}'.format(id)
        headers = {
            'vmware-api-session-id': self.session_id
        }
        try:
            response = requests.request("GET", url, headers=headers, verify=False)
            if response.status_code == 200:
                return response.text
        except Exception as exp:
            logger.error(exp)
            return None
    
    def is_valid_folder_id(self, id):
        url = self.base_url + 'folder?folders={}&type=VIRTUAL_MACHINE'.format(id)
        headers = {
            'vmware-api-session-id': self.session_id
        }
        try:
            response = requests.request("GET", url, headers=headers, verify=False)
            if response.status_code == 200:
                return response.text != '[]'
        except Exception as exp:
            logger.error(exp)
            return None
    
    def is_valid_vm_id(self, id):
        url = self.base_url + 'vm/{}'.format(id)
        headers = {
            'vmware-api-session-id': self.session_id
        }
        try:
            response = requests.request("GET", url, headers=headers, verify=False)
            if response.status_code == 200:
                return response.json()['identity']['name'] == self.main_config["App/Web Server Configs"]["source_vm_name"]
        except Exception as exp:
            logger.error(exp)
            return None
    
    def get_authorization_token(self, thunder_ip, username, password):
        # AXAPI header
        axapi_base_url = "https://%s/axapi/v3" % thunder_ip
        headers = {
            "accept": "application/json",
            "Content-Type": "application/json"
        }
        # AXAPI Auth url json body
        data = {
            "credentials": {
                "username": username,
                "password": password
            }
        }
        url = "".join([axapi_base_url, "/auth"])
        try:
            response = requests.post(url, headers=headers, data=json.dumps(data), verify=False)
        except Exception as e:
            logger.error('Failed to get authorization token for thunder. [Invalid Management IP %s provided in config.ini]' % thunder_ip)
            # logger.error(e)
        else:
            if response.status_code != 200:
                logger.error("Failed to get authorization token from AXAPI for thunder %s [Invalid vThunder credentials in config.ini]" % thunder_ip)
            else:
                authorization_token = json.loads(response.text)["authresponse"]["signature"]
                return authorization_token
    
    def thunder_logoff(self, thunder_ip, authorization_token):
        """
        function to check if partition exists
        :param partition_name:
        :return True/False:
        """
        headers = {
            "Authorization": "".join(["A10 ", authorization_token]),
            "accept": "application/json",
            "Content-Type": "application/json"
        }
        axapi_base_url = "https://%s/axapi/v3" % thunder_ip
        url = "".join([axapi_base_url, "/logoff"])
        try:
            response = requests.get(url=url, headers=headers, verify=False)
            if response.status_code == 200:
                return True
        except Exception as exp:
            logger.error("Failed to logoff from vThunder %s" % thunder_ip)
            logger.error(exp)
            return False

    def is_partition_exist(self, partition_name, thunder_ip, authorization_token):
        """
        function to check if partition exists
        :param partition_name:
        :return True/False:
        """
        
        if partition_name == 'shared':
            return True
        axapi_base_url = "https://%s/axapi/v3" % thunder_ip
        headers = {
            "Authorization": "".join(["A10 ", authorization_token]),
            "accept": "application/json",
            "Content-Type": "application/json"
        }
        url = "".join([axapi_base_url, "/partition/", partition_name])
        try:
            response = requests.get(url=url, headers=headers, verify=False)
            if response.status_code == 200:
                return True
            else:
                logger.error("Partiton '%s' does not exist on vThunder %s." % (partition_name, thunder_ip))
                return False
        except Exception as exp:
            logger.error("Failed to get partitions details from vThunder %s" % thunder_ip)
            logger.error(exp)
            return False
    
    def field_validations(self):
        try: 
            self.validate_config(config=self.vcenter_config, file_name="vcenter.ini")
            self.validate_config(config=self.main_config, file_name="config.ini")
            source_vm_os = self.main_config["App/Web Server Configs"]["source_vm_os"].lower()
            source_vm_id = self.main_config["App/Web Server Configs"]["source_vm_id"]
            server_subnet = self.main_config["App/Web Server Configs"]["server_subnet"]
            source_transit_ip = self.main_config["App/Web Server Configs"]["source_transit_ip"]
            service_up_timeout = eval(self.main_config["App/Web Server Configs"]["service_up_timeout"])
            
            subnet_network = ipaddress.IPv4Network(server_subnet)
            ip_address = ipaddress.IPv4Address(source_transit_ip)
            # Check if the IP address belongs to the subnet
            if ip_address not in subnet_network:
                raise Exception("'server_subnet' and 'source_transit_ip' are not in the same subnet in config.ini. [Invalid 'server_subnet' subnet should be of format 'x.x.x.x/x']")

            cluster_id = self.main_config["vCenter Inventory"]["cluster_id"]
            datastore_id = self.main_config["vCenter Inventory"]["datastore_id"]
            folder_id = self.main_config["vCenter Inventory"]["folder_id"]
            
            cool_down = eval(self.main_config["AutoScale Configs"]["cool_down"])
            minimum_replica = eval(self.main_config["AutoScale Configs"]["minimum_replica"])
            maximum_replica = eval(self.main_config["AutoScale Configs"]["maximum_replica"])
            graceful_scale_in_time = eval(self.main_config["AutoScale Configs"]["graceful_scale_in_time"])
            
            thunder_ips = self.main_config["Thunder Configs"]["thunder_ip"]
            if type(thunder_ips) != list:
                thunder_ips = [thunder_ips]
            thunder_ips = set(thunder_ips)
            thunder_username = self.main_config["Thunder Configs"]["thunder_username"]
            thunder_password = self.main_config["Thunder Configs"]["thunder_password"]
            thunder_partition_name = self.main_config["Thunder Configs"]["thunder_partition_name"]
            
            if(len(thunder_ips) == 0):
                raise Exception("Provide atleast one ip in 'thunder_ip' in config.ini")
            
            for ip in thunder_ips:
                auth_token = self.get_authorization_token(thunder_ip=ip, username=thunder_username, password=thunder_password)
                if not auth_token:
                    return False
                if not self.is_partition_exist(partition_name=thunder_partition_name, thunder_ip=ip, authorization_token=auth_token):
                    self.thunder_logoff(thunder_ip=ip, authorization_token=auth_token)
                    return False
                self.thunder_logoff(thunder_ip=ip, authorization_token=auth_token)
            
            # return False
            if type(service_up_timeout) != int or service_up_timeout < 0:
                raise Exception("'service_up_timeout' should be greater than or equal to 0 seconds in config.ini")
            if type(cool_down) != int or cool_down < (service_up_timeout + 120):
                raise Exception("'cool_down' should be greater than %s seconds in config.ini" % (service_up_timeout + 120))
            if type(graceful_scale_in_time) != int or graceful_scale_in_time < 0:
                raise Exception("'graceful_scale_in_time' should be greater than or equal to 0 seconds in config.ini")
            if type(minimum_replica) != int or minimum_replica < 1:
                raise Exception("'minimum_replica' should be greater than 0 in config.ini")
            if type(maximum_replica) != int or maximum_replica < minimum_replica:
                raise Exception("'maximum_replica' should be greater than or equal to 'minimum_replica' in config.ini")
            if source_vm_os not in ['ubuntu', 'rhel', 'centos']:
                raise Exception("'source_vm_os' can be either ubuntu, centos or rhel in config.ini")
            if not self.is_valid_vm_id(source_vm_id):
                raise Exception("Invalid 'source_vm_id' or 'source_vm_name' in config.ini, VM does not exist or source_vm_name is different corresponding to source_vm_id.")
            if not self.is_valid_cluster_id(cluster_id):
                raise Exception("Invalid 'cluster_id' in config.ini, Cluster does not exist.")
            if not self.is_valid_datastore_id(datastore_id):
                raise Exception("Invalid 'datastore_id' in config.ini, Datastore does not exist.")
            if not self.is_valid_folder_id(folder_id):
                raise Exception("Invalid 'folder_id' in config.ini, Folder does not exist.")
            if not self.check_vcenter_vm():
                return False
            return True
        except Exception as e:
            logger.error(e)
            return False

if __name__ == '__main__':
    try:
        start_time = time.time()
        logger.info("Starting deployment...")
        current_directory = os.path.dirname(os.path.abspath(__file__))
        vcenter_config_loc = os.path.join(current_directory, 'a10_vcenter_backauto_plugin', 'vcenter.ini')
        config_file_loc = os.path.join(current_directory, 'a10_vcenter_backauto_plugin', 'apps', 'app1', 'config.ini')
        vcenter_config = ConfigObj(vcenter_config_loc)
        main_config = ConfigObj(config_file_loc)
        dm = DeploymentManager(vcenter_config=vcenter_config, main_config=main_config)
        if(dm.session_id == None):
            raise Exception("Invalid 'vcenter_server_ui_username' or 'vcenter_server_ui_password' or 'vcenter_server_ip' in vcenter.ini [Unable to create session with vcenter server]")
        if(not dm.field_validations()):
            exit(0)
        vm_id = dm.clone_server()
        if not vm_id:
            raise Exception("Invalid 'source_vm_id' or VM with name provided in 'clone_vm_name' in vcenter.ini file already exists. [Unable to create clone of source VM]")
        vm_id = vm_id.replace('"', '')
        main_config['App/Web Server Configs']['clone_vm_id'] = vm_id
        main_config.write()
        dm.upload()
        dm.grant_access_permissions()
        dm.setup_virtualenv()
        logger.info("Finished deployment!")
        end_time = time.time()
        logger.info("Total time taken for deployment %s seconds" % (end_time-start_time))
    except Exception as e:
        logger.error(e)
    finally:
        if dm.session_id:
            dm.delete_session()
