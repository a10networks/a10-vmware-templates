#!/backautovenv/bin/python3
"""
Script to add/delete app server in Thunder SLB configuration.
"""
import json
import os
import time

import requests
from plugins.utils.logger import logger


class ThunderManager:
    # keep this same as remote_path value present in deployment.ini
    # current_working_directory = '/AppServerAutoScale'

    def __init__(self, mgmt_ip, username, password, configurations):
        self.thunder_ip = mgmt_ip
        self.username = username
        self.password = password
        self.configurations = configurations
        self.axapi_base_url = "https://%s/axapi/v3" % self.thunder_ip
        self.is_partition_activated = False
        self.authorization_token = self.get_authorization_token()
        if self.authorization_token:
            self.activate_partition()

    def get_authorization_token(self):
        # AXAPI header
        headers = {
            "accept": "application/json",
            "Content-Type": "application/json"
        }
        # AXAPI Auth url json body
        data = {
            "credentials": {
                "username": self.username,
                "password": self.password
            }
        }
        url = "".join([self.axapi_base_url, "/auth"])
        try:
            response = requests.post(url, headers=headers, data=json.dumps(data), verify=False)
        except Exception as e:
            logger.error('Failed to get authorization token for vThunder. [Invalid Management IP %s provided in config.ini]' % self.thunder_ip)
        else:
            if response.status_code != 200:
                logger.error("Failed to get authorization token from AXAPI for vThunder %s [Invalid vThunder credentials in config.ini]" % self.thunder_ip)
            else:
                authorization_token = json.loads(response.text)["authresponse"]["signature"]
                return authorization_token
        return None
    
    def logoff(self):
        """
        function to check if partition exists
        :param partition_name:
        :return True/False:
        """
        headers = {
            "Authorization": "".join(["A10 ", self.authorization_token]),
            "accept": "application/json",
            "Content-Type": "application/json"
        }
        url = "".join([self.axapi_base_url, "/logoff"])
        try:
            response = requests.get(url=url, headers=headers, verify=False)
            if response.status_code == 200:
                return True
        except Exception as exp:
            logger.error("Failed to logoff from vThunder %s" % self.thunder_ip)
            logger.error(exp)
            return False
    
    def is_partition_exist(self, partition_name):
        """
        function to check if partition exists
        :param partition_name:
        :return True/False:
        """
        if partition_name == 'shared':
            return True
        headers = {
            "Authorization": "".join(["A10 ", self.authorization_token]),
            "accept": "application/json",
            "Content-Type": "application/json"
        }
        url = "".join([self.axapi_base_url, "/partition/", partition_name])
        try:
            response = requests.get(url=url, headers=headers, verify=False)
            if response.status_code == 200:
                return True
            else:
                logger.error("Partiton '%s' does not exist in vThunder %s." % (partition_name, self.thunder_ip))
                return False
        except Exception as exp:
            logger.error("Failed to get partitions details from vThunder %s" % self.thunder_ip)
            logger.error(exp)
            return False

    def activate_partition(self):
        """
        function to activate a partition
        :return:
        """
        partition_name = self.configurations.get('Thunder Configs', 'thunder_partition_name')
        if not self.is_partition_exist(partition_name):
            return
        headers = {
            "Authorization": "".join(["A10 ", self.authorization_token]),
            "accept": "application/json",
            "Content-Type": "application/json"
        }
        url = "".join([self.axapi_base_url, "/active-partition"])
        body = {
            "active-partition": {}
        }
        if partition_name.lower() == 'shared':
            body['active-partition']['shared'] = 1
        else:
            body['active-partition']['curr_part_name'] = partition_name
        try:
            response = requests.post(url=url, headers=headers, data=json.dumps(body), verify=False)
            if response.status_code == 204 or response.status_code == 200:
                self.is_partition_activated = True
                logger.info("Activated partition %s in vThunder %s" % (partition_name, self.thunder_ip))
            else:
                # logger.error(response.text)
                raise Exception("Failed to activate partition %s in vThunder" % (partition_name, self.thunder_ip))
        except Exception as exp:
            logger.error(exp)

    def get_server_ip(self, server_name):
        headers = {
            "Authorization": "".join(["A10 ", self.authorization_token]),
            "accept": "application/json",
            "Content-Type": "application/json"
        }
        # server AXAPI
        url = "".join([self.axapi_base_url, "/slb/server/", server_name])
        try:
            response = requests.get(url=url, headers=headers, verify=False)
            if response.status_code == 200:
                response = response.json()
                if response:
                    return response['server']['host']
            logger.error("Server %s does not exist in slb config of vThunder %s" % (server_name, self.thunder_ip))
            return None
        except Exception as exp:
            logger.error(exp)
            return None
            
    def get_reference_server(self):
        reference_server = self.configurations.get('App/Web Server Configs', 'source_vm_name')
        headers = {
            "Authorization": "".join(["A10 ", self.authorization_token]),
            "accept": "application/json",
            "Content-Type": "application/json"
        }
        url = "".join([self.axapi_base_url, "/slb/server/", reference_server])
        try:
            response = requests.get(url=url, headers=headers, verify=False)
            if response.status_code == 200:
                return response.json()['server']
            else:
                logger.error('Failed to get reference server %s in vThunder %s.' % (reference_server, self.thunder_ip))
                # logger.error(response.text)
                return None
        except Exception as exp:
            logger.error(exp)
            return None

    def get_service_groups(self):
        headers = {
            "Authorization": "".join(["A10 ", self.authorization_token]),
            "accept": "application/json",
            "Content-Type": "application/json"
        }
        url = "".join([self.axapi_base_url, "/slb/service-group"])
        try:
            response = requests.get(url=url, headers=headers, verify=False)
            if response.status_code == 200:
                return response.json()['service-group-list']
            else:
                logger.error('Failed to get configured service'
                             ' groups in vThunder %s' % self.thunder_ip)
                # logger.error(response.text)
                return None
        except Exception as exp:
            logger.error(exp)
            return None

    def config_server(self, server):
        headers = {
            "Authorization": "".join(["A10 ", self.authorization_token]),
            "accept": "application/json",
            "Content-Type": "application/json"
        }
        # server AXAPI
        url = "".join([self.axapi_base_url, "/slb/server/"])
        server_details = self.get_reference_server()
        if not server_details:
            return False
        server_details['name'] = server['name']
        server_details['host'] = server['ip_address']
        data = {
            "server": server_details
        }
        try:
            response = requests.post(url=url, headers=headers, data=json.dumps(data), verify=False)
            if response.status_code == 200:
                logger.debug('configured server: %s in vThunder %s' % (server['name'], self.thunder_ip))
            else:
                logger.error('Failed to configure server %s in vThunder %s' % (server['name'], self.thunder_ip))
                logger.error(response.json()['err']['msg'])
        except Exception as exp:
            logger.error(exp)
            # return with error
            return False
        
        time.sleep(6)

        service_group_list = self.get_service_groups()
        if not service_group_list:
            return False
        isconfigured = False
        for service_group in service_group_list:
            existing_members = service_group.get('member-list', [])
            for each_member in existing_members:
                if each_member['name'] == self.configurations.get('App/Web Server Configs',
                                                                  'source_vm_name'):
                    # AXAPI for adding member
                    # add server as member to service groups
                    url = "".join([self.axapi_base_url, '/slb/service-group/' + service_group['name'] + '/member'])

                    # member body
                    member = {
                        "name": server["name"],
                        "port": each_member["port"]
                    }
                    data = {
                        "member": member
                    }
                    try:
                        response = requests.post(url=url, headers=headers, data=json.dumps(data), verify=False)
                        if response.status_code == 200:
                            logger.debug('added server: %s as member of sg: %s in vThunder %s' % (server['name'], service_group['name'], self.thunder_ip))
                            isconfigured = True
                        else:
                            logger.error('Failed to add server %s as a member of service group %s in vThunder %s' % (
                                server['name'], service_group['name'], self.thunder_ip
                            ))
                            logger.error(response.json()['err']['msg'])
                    except Exception as exp:
                        logger.error(exp)
        return isconfigured

    def remove_server_config(self, server_name):
        headers = {
            "Authorization": "".join(["A10 ", self.authorization_token]),
            "accept": "application/json",
            "Content-Type": "application/json"
        }
        url = "".join([self.axapi_base_url, "/slb/server/", server_name])

        response = requests.delete(url=url, headers=headers, verify=False)
        if response.status_code == 200:
            logger.info('Removed server %s from slb configuration in vThunder %s.' % (server_name, self.thunder_ip))
        elif response.status_code == 404:
            logger.error('Server %s configuration does not exist in vThunder %s' % (server_name, self.thunder_ip))
        else:
            logger.error('Failed to remove server %s from slb configuration in vThunder %s' % (server_name, self.thunder_ip))
            logger.error(response.json()['err']['msg'])
            
    def disable_enable_server(self, server_name, action):
        headers = {
            "Authorization": "".join(["A10 ", self.authorization_token]),
            "accept": "application/json",
            "Content-Type": "application/json"
        }
        url = "".join([self.axapi_base_url, "/slb/server/", server_name])
        data = {
                    "server": {
                        "action": action
                    }
                }
        response = requests.post(url=url, headers=headers, data=json.dumps(data), verify=False)
        if response.status_code == 200:
            logger.info('Successfully %s server %s in vThunder %s.' % (action, server_name, self.thunder_ip))
        else:
            logger.error('Failed to %s server %s in vThunder %s.' % (action, server_name, self.thunder_ip))
            logger.error(response.json()['err']['msg'])
            
    def get_server_conn_count(self, server_name):
        headers = {
            "Authorization": "".join(["A10 ", self.authorization_token]),
            "accept": "application/json",
            "Content-Type": "application/json"
        }
        url = "".join([self.axapi_base_url, "/slb/server/", server_name, "/stats"])
        
        try:
            response = requests.get(url=url, headers=headers, verify=False)
            if response.status_code == 200:
                return response.json()['server']["stats"]["curr-conn"]
            else:
                logger.error('Failed to get current connection count '
                             'for server %s in vThunder %s' % (server_name, self.thunder_ip))
                logger.error(response.text)
                return 0
        except Exception as exp:
            logger.error(exp)
            return 0

    def write_memory(self):
        headers = {
            "Authorization": "".join(["A10 ", self.authorization_token]),
            "accept": "application/json",
            "Content-Type": "application/json"
        }
        
        partition = self.configurations.get('Thunder Configs', 'thunder_partition_name')
        if not partition:
            logger.error("Failed to get partition name")
        else:
            url = "".join([self.axapi_base_url, "/write/memory"])
            data = {
                "memory": {
                    "partition": "specified",
                    "specified-partition": partition
                }
            }
            try:
                response = requests.post(url, headers=headers,
                                         data=json.dumps(data), verify=False)
                if response.status_code == 200:
                    logger.info("Configurations are saved on partition %s in vThunder %s" % (partition, self.thunder_ip))
                else:
                    logger.error("Failed to run write memory command in vThunder %s" % (self.thunder_ip))
            except Exception as e:
                logger.error('Error in writing to memory : ', exc_info=True)
