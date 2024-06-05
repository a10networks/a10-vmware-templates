#!/backautovenv/bin/python3
"""
Script to scale in app server and remove deleted app server configuration from Thunder devices
"""
import os
import sys

sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))))

import time
import requests
from collections import Counter

from plugins.thunder.thunder import ThunderManager
from plugins.utils.virtual_machine import VirtualMachine
from plugins.vcenter.config_manager import ConfigManager
from plugins.utils.logger import logger
from plugins.vcenter.session_manager import SessionManager

import warnings
warnings.filterwarnings('ignore')


class ScaleInAppServer:
    def __init__(self, config, app_servers, vcenter_config, session):
        self.config = config
        self.app_servers = app_servers
        self.vcenter_config = vcenter_config
        self.session_id = session
        self.vcenter_ip = self.vcenter_config.get('vCenter Configs', 'vcenter_server_ip')
        self.base_url = "https://{}/api/vcenter/".format(self.vcenter_ip)

    def select_vm_to_scale_in(self, vms):
        """
        function to choose a vm to delete
        :param vms:
        :return vm_id:
        """
        if len(vms) <= 1:
            self.vm = vms[-1]
            if self.vm['name'] == self.config.get('App/Web Server Configs', 'source_vm_name'):
                raise Exception("No vm found to scale in.")
        else:
            self.vm = vms[-1]
            if self.vm['name'] == self.config.get('App/Web Server Configs', 'source_vm_name'):
                self.vm = vms[-2]

        self.vm_id, self.vm_name = self.vm['vm'], self.vm['name']
        return self.vm_id, self.vm_name

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


if __name__ == '__main__':
    try:
        start_time = time.time()
        logger.info("Scale In operation triggered.")
        # get configurations
        app_name = os.path.basename(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        cfg = ConfigManager(app_name=app_name)
        configuration, app_servers, vcenter_config = cfg.get_configs()
        # get vcenter session
        cool_down = eval(configuration.get('AutoScale Configs', 'cool_down'))
        last_scaling_timestamp = float(eval(app_servers.get('AppServer', 'last_scaling_timestamp')))
        logger.debug('cool down time is %s' % (cool_down))
        current_timestamp = time.time()
        session_id = ""
        logger.debug('time from last scaling operation is %s' % (current_timestamp - last_scaling_timestamp))
        if (current_timestamp - last_scaling_timestamp) < cool_down:
            logger.warning("scale in operation failed because operation triggered within cool down period.")
            exit(0)

        # update last scale in timestamp
        cfg.set_config(section='AppServer',
                                    key='last_scaling_timestamp',
                                    value=str(current_timestamp))

        session = SessionManager(config=vcenter_config)
        session_id = session.get_session()
        # initialize VirtualMachine class object
        folder = configuration.get('vCenter Inventory', 'folder_id')

        min_scale_in = eval(configuration.get('AutoScale Configs', 'minimum_replica'))
        vm = VirtualMachine(session_id=session_id, vcenter_config=vcenter_config)

        # get list of all vms present in folder
        vm_list = vm.list_all_vms(folder=folder)

        if min_scale_in >= len(vm_list):
            logger.warning("scale in operation failed because scale in capacity limit reached.")
            exit(0)

        # Create class objects
        scalein = ScaleInAppServer(config=configuration,
                                app_servers=app_servers,
                                vcenter_config=vcenter_config,
                                session=session_id)

        # check if currently no vm is present in folder
        if len(vm_list) > 1:
            # get last vm id
            vm_id, vm_name = scalein.select_vm_to_scale_in(vms=vm_list)
            
            thunder_ip_addresses = configuration.get('Thunder Configs', 'thunder_ip')
            if ',' in thunder_ip_addresses:   
                thunder_ip_addresses = thunder_ip_addresses.replace(' ', '')
                thunder_ip_addresses = thunder_ip_addresses.split(',')
            if type(thunder_ip_addresses) != list:
                thunder_ip_addresses = [thunder_ip_addresses]
            duplicates = [item for item, count in Counter(thunder_ip_addresses).items() if count > 1]
            if duplicates:
                logger.warning("Duplicate vThunder IP addresses %s found in 'thunder_ip' in config.ini." % duplicates)
            
            thunder_ip_addresses = set(thunder_ip_addresses)
            thunder_username = configuration.get('Thunder Configs', 'thunder_username')
            thunder_password = configuration.get('Thunder Configs', 'thunder_password')

            current_conn_count = 0
            thunder_objs = []
            for thunder_ip in thunder_ip_addresses:
                thunder = ThunderManager(mgmt_ip=thunder_ip, username=thunder_username,
                                            password=thunder_password,
                                            configurations=configuration)
                if thunder.is_partition_activated:
                    thunder_objs.append(thunder)
                    thunder.disable_enable_server(server_name=vm_name, action="disable")
                    current_conn_count += thunder.get_server_conn_count(server_name=vm_name)
                
            # max wait time in seconds
            max_wait_time = eval(configuration.get('AutoScale Configs', 'graceful_scale_in_time'))
            current_time = 0
            # wait till vm active session gets completed.
            while current_conn_count != 0:
                if current_time >= max_wait_time:
                    for thunder in thunder_objs:
                        thunder.disable_enable_server(server_name=vm_name, action="enable")
                        thunder.logoff()
                        # del thunder
                    raise Exception("Current session are still running, Failed to power off vm %s." % vm_name)

                time.sleep(30)
                current_time += 30
                current_conn_count = 0
                logger.info("Waiting for active sessions to complete in vm %s." % vm_name)
                for thunder in thunder_objs:
                    current_conn_count += thunder.get_server_conn_count(server_name=vm_name)
                    # del thunder

            logger.info("All session are closed in vm %s." % vm_name)
            max_wait_time = 120
            current_time = 0
            # check if vm is powered off, if not then power off vm
            while not vm.is_vm_powered_off(vm_id=vm_id):
                if current_time >= max_wait_time:
                    raise Exception("Failed to power off vm %s." % vm_name)
                status_check = vm.power_off_vm(vm_id=vm_id)
                if status_check == 204:
                    logger.info("Powered off vm %s." % vm_name)
                    
                time.sleep(10)
                current_time += 10
                
            
            for thunder in thunder_objs:
                server_ip = thunder.get_server_ip(vm_name)
                if server_ip:
                    thunder.remove_server_config(server_name=vm_name)
                    thunder.write_memory()
                    thunder.logoff()
                
            status = vm.delete_vm(vm_id=vm_id)
            if status == 204:
                scalein.remove_ip(server_ip)
                logger.info('Successfully deleted vm {}.'.format(vm_name))
            else:
                logger.error('Failed to delete VM, Scale in operation failed.')
        else:
            logger.error('No vm found in folder {} to scale in'.format(folder))

        logger.info("Finished scale in operation.")
    except Exception as exp:
        logger.error(exp)
    finally:
        if session_id:
            session.delete_session(session_id=session_id)
        end_time = time.time()
        logger.info("Total time taken: %s seconds" % (end_time - start_time))
