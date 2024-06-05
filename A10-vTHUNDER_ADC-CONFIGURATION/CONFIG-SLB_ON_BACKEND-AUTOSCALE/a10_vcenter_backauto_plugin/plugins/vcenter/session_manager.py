#!/backautovenv/bin/python3
"""
Python module to manage vcenter session.
"""
import requests
from requests.auth import HTTPBasicAuth

from plugins.utils.logger import logger


class SessionManager:
    def __init__(self, config):
        vcenter_ip = config.get('vCenter Configs', 'vcenter_server_ip')
        self.base_url = "https://{}/api/".format(vcenter_ip)
        self.username = config.get('vCenter Configs', 'vcenter_server_ui_username')
        self.password = config.get('vCenter Configs', 'vcenter_server_ui_password')

    def __create_session(self):
        """
        function to create vsphere vcenter session
        :return session_id:
        """
        url = self.base_url + 'session/'
        headers = {
            'Content-Type': 'application/json'
        }
        response = requests.request("POST", url, headers=headers,
                                    auth=HTTPBasicAuth(self.username, self.password),
                                    verify=False)

        if response.status_code == 201:
            response = response.json()
            logger.info("Created session with vCenter VM %s" % response)
            return response
        return None

    def delete_session(self, session_id):
        """
        function to delete vsphere vcenter session
        :return status_code:
        """
        url = self.base_url + 'session'
        headers = {
            'vmware-api-session-id': session_id
        }
        response = requests.delete(url=url, headers=headers, verify=False)
        if response.status_code == 204:
            logger.info('Deleted session %s' % session_id)
        return response.status_code

    def get_session(self):
        # if not SessionManager.session:
        session = self.__create_session()
        return session
