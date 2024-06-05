#!/backautovenv/bin/python3
"""
VMware vSphere vCenter Virtual Machine extra utilities Module.
"""
import requests
import paramiko


class VirtualMachine:
    def __init__(self, session_id, vcenter_config):
        self.session_id = session_id
        self.vcenter_config = vcenter_config
        self.vcenter_ip = self.vcenter_config.get('vCenter Configs', 'vcenter_server_ip')
        self.base_url = "https://{}/api/vcenter/".format(self.vcenter_ip)

    def list_all_vms(self, folder):
        """
        function to list down all vcenter vms of a folder
        :param folder:
        :return json:
        """
        url = self.base_url + 'vm?folders={}&power_states=POWERED_ON'.format(folder)
        headers = {
            'vmware-api-session-id': self.session_id
        }
        response = requests.request("GET", url, headers=headers, verify=False)
        return response.json()

    def is_vm_powered_off(self, vm_id):
        """
        function to check if vm is powered off
        :param vm_id:
        :return boolean:
        """
        url = self.base_url + 'vm/{}'.format(vm_id)
        headers = {
            'vmware-api-session-id': self.session_id
        }
        response = requests.request("GET", url, headers=headers, verify=False)
        if response.status_code == 200:
            response_data = response.json()
            if response_data['power_state'] == 'POWERED_OFF':
                return True
        return False

    def power_off_vm(self, vm_id):
        """
        function to power off a virtual machine
        :param vm_id:
        :return status_code:
        """
        url = self.base_url + 'vm/{}/guest/power?action=shutdown'.format(vm_id)
        headers = {
            'vmware-api-session-id': self.session_id
        }
        response = requests.request("POST", url, headers=headers, verify=False)
        return response.status_code
    
    def delete_vm(self, vm_id):
        """
        function to delete a virtual machine
        :return status_code:
        """
        url = self.base_url + 'vm/{}'.format(vm_id)
        headers = {
            'Content-Type': 'application/json',
            'vmware-api-session-id': self.session_id
        }
        response = requests.request("DELETE", url, headers=headers, verify=False)
        return response.status_code
