"""
--------SCRIPT TO CONFIGURE THUNDER DEVICE AS A SLB--------
Functions:
    [a] Function for SLB Configuration on vthunder
    1. get_auth_token
    2. configure_ethernet
    3. configure_server
    4. configure_service_group
    5. configure_virtual_server
    6. configure_http_template
    7. configure_slb_persist_cookie

    [b] Function to save configuration to memory
    1. write_memory
"""

from logger import logger
import warnings
import json
import requests
import getpass
import HTTP_TEMPLATE
import PERSIST_COOKIE

warnings.filterwarnings('ignore')


def validate_load_json():
    """
    This function will validate and load parameter file's contents.
    :return:
    """
    try:
        parameter_file = open('SLB_CONFIG_PARAM.json')
        SLB_data = json.load(parameter_file)
        if 'parameters' in SLB_data:
            if 'publicIpList' not in SLB_data['parameters']:
                print("public ip is not provided.")
                return None
            if 'data_interface_count' not in SLB_data['parameters']:
                print("interface count is not provided.")
                return None
            if 'slbServerPortList' not in SLB_data['parameters']:
                print("server list is not provided.")
                return None
            if 'serviceGroupList' not in SLB_data['parameters']:
                print("service group list is not provided.")
                return None
            if 'virtualServerList' not in SLB_data['parameters']:
                print("virtual server list is not provided.")
                return None
        else:
            print("No parameters provided in file.")
            return None
        return SLB_data
    except Exception as ex:
        logger.error(ex)
        return None


def get_auth_token(username, password, base_url):
    """
    Function to get authorization token.
    :param username: username for vthunder instance
    :param password: password of vthunder
    :param base_url: vthunder base url to access axapi
    :return: Authorization token
    AXAPI: /axapi/v3/auth
    """
    # AXAPI header
    headers = {
        "accept": "application/json",
        "Content-Type": "application/json"
    }
    # AXAPI Auth url json body
    data = {"credentials": {
        "username": username,
        "password": password
    }
    }
    url = "".join([base_url, "/auth"])
    try:
        response = requests.post(url, headers=headers,
                                 data=json.dumps(data), verify=False)
        if response.status_code != 200:
            logger.error('Failed to get authorization token from AXAPI')
            print('Failed to get authorization token from AXAPI')
        else:
            authorization_token = json.loads(response.text)["authresponse"]["signature"]
            return authorization_token
    except Exception as e:
        logger.error('Error in authentication token: ', exc_info=True)


def vth_logout(base_url, authorization_token):
    """
     Function to logout vthunder session
    :param base_url: vthunder base url to access axapi
    :param authorization_token: authorization token
    :return 200
    """
    url = f"{base_url}/logoff"
    payload = {}

    headers = {
        "Authorization": "".join(["A10 ", authorization_token]),
        "Content-Type": "application/json"
    }

    try:
        response = requests.request("GET", url, headers=headers, data=payload, verify=False)
        if response.status_code != 200:
            logger.error('Failed to logout vThunder')
            logger.error(response.text)
            return False
        else:
            print("Successfully logged out from vThunder.")
            return True
    except Exception as e:
        logger.error(e)
        return False


# ------------------------------- SLB Configuration ----------------------
def configure_ethernets(base_url, authorization_token, vthunder_addresses, data_interface_count):
    """
        This function will configure ethernet
        :param base_url: vthunder base url to access axapi
        :param authorization_token: authorization token
        :param vthunder_addresses: vthunder address
        :param data_interface_count: number of data interface
        AXAPI: /interface/ethernet/<ethernet_number>
        :return:
    """

    # AXAPI interface url headers
    header = {
        "Authorization": "".join(["A10 ", authorization_token]),
        "accept": "application/json",
        "Content-Type": "application/json"
    }
    # for each private ip address and add configuration in ethernet list
    ethernet_number = 1
    data_interface_count = data_interface_count + 1
    while ethernet_number < data_interface_count:
        if ethernet_number == 1:
            address_list = vthunder_addresses['ethernet1-addresses']
            print(address_list)
        else:
            address_list = vthunder_addresses['ethernet2-addresses']
        # AXAPI ethernets Url
        url = "".join([base_url, "/interface/ethernet/" + str(ethernet_number)])
        body = {
            "ethernet": {
                "ifnum": ethernet_number,
                "action": "enable",
                "ip": {
                    "dhcp": 0,
                    "address-list": address_list
                }
            }
        }
        # Invoke interface AXAPI
        try:
            response = requests.post(
                url, headers=header, data=json.dumps(body), verify=False)
            if response.status_code != 200:
                logger.error("Failed to configure ethernet- " + str(ethernet_number) + " ip")
                logger.error(response.text)
            else:
                logger.info("configured ethernet- " + str(ethernet_number) + " ip")
                print("configured ethernet- " + str(ethernet_number) + " ip")
            # increase ethernet number by 1
            ethernet_number += 1

        except Exception as e:
            logger.error('Error in configuring ethernet: ', exc_info=True)


def configure_server(SLB_param_data, base_url, authorization_token, server_pvt_ip_list, server_name_list):
    """
    Function to configure server
    :param SLB_param_data: parameters loaded from parameter file.
    :param base_url: Base url of AXAPI
    :param authorization_token: authorization token
    :param server_pvt_ip_list: private ip of server
    :param server_name_list: server name
    :return:
    AXAPI: /axapi/v3/slb/server
    """
    headers = {
        "Authorization": "".join(["A10 ", authorization_token]),
        "accept": "application/json",
        "Content-Type": "application/json"
    }
    server_details = {}
    port_list = SLB_param_data["parameters"]["slbServerPortList"]["value"]
    i = 0
    for server in server_name_list:
        server_details["name"] = server
        server_details['host'] = server_pvt_ip_list[i]
        server_details['port-list'] = SLB_param_data["parameters"]["slbServerPortList"]["value"]
        data = {"server": server_details}
        url = "".join([base_url, "/slb/server"])
        try:
            response = requests.post(url, headers=headers,
                                     data=json.dumps(data), verify=False)
            if response.status_code == 200:
                logger.info('Configured server ' + server)
                print('Successfully configured server ' + server)
                i = i + 1
                for each_port in port_list:
                    # create service group name
                    sg_name = "sg" + str(each_port['port-number'])

                    # check if service group exists
                    # else create service group
                    url = base_url + '/slb/service-group/'
                    response = requests.get(url, headers=headers, verify=False)

                    existing_service_groups = set()
                    if response.text:
                        service_groups = json.loads(response.text)
                        for sg in service_groups['service-group-list']:
                            existing_service_groups.add(sg['name'])
                    # AXAPI for adding member
                    url = base_url + '/slb/service-group/' + sg_name + '/member'

                    # member body
                    member = {
                        "name": server,
                        "port": each_port["port-number"]
                    }
                    data = {
                        "member": member
                    }
                    try:
                        response = requests.post(url=url, headers=headers, data=json.dumps(data), verify=False)
                        if response.status_code == 200:
                            logger.info('added server: %s as member of sg: %s' % (server, sg_name))
                        else:
                            logger.error(
                                'Falied to add server %s as a member of service group %s' % (server['name'], sg_name))
                            logger.error(response.text)

                    except Exception as e:
                        logger.error('Error in adding server as a member of the service group: ', exc_info=True)

            else:
                logger.error("Failed to configure server " + server)
                logger.error(response.text)
                i = i + 1


        except Exception as e:
            logger.error('Error in configuring server: ', exc_info=True)


def configure_service_group(SLB_param_data, base_url, authorization_token):
    """
    Function to configure service group
    :param SLB_param_data: parameters loaded from parameter file.
    :param base_url: Base url of AXAPI
    :param authorization_token: authorization token
    :return:
    AXAPI: /axapi/v3/slb/service-group
    """
    headers = {
        "Authorization": "".join(["A10 ", authorization_token]),
        "accept": "application/json",
        "Content-Type": "application/json"
    }
    url = "".join([base_url, "/slb/service-group"])
    service_groups = SLB_param_data["parameters"]["serviceGroupList"]["value"]
    data = {
        "service-group-list": service_groups
    }
    try:
        response = requests.post(url, headers=headers,
                                 data=json.dumps(data), verify=False)
        if response.status_code != 200:
            logger.error("Failed to configure service group")
            logger.error(response.text)
        else:
            logger.info("Configured service group")
            print("Successfully configure service group.")
    except Exception as e:
        logger.error('Error in configuring service group: ', exc_info=True)
        logger.error(e)


def configure_virtual_server(SLB_param_data, base_url, authorization_token, vThunder1_sec_ips, virtual_server_ports):
    """
    Function to configure virtual servers
    :param SLB_param_data: parameters loaded from parameter file.
    :param base_url: Base url of AXAPI
    :param authorization_token: authorization token
    :param vThunder1_sec_ips : vThunder1's secondary private ips
    :param virtual_server_ports: virtual server ports
    :return:
    AXAPI: /axapi/v3/slb/virtual-server
    """
    headers = {
        "Authorization": "".join(["A10 ", authorization_token]),
        "accept": "application/json",
        "Content-Type": "application/json"
    }
    url = "".join([base_url, "/slb/virtual-server"])
    virtual_server_ip = vThunder1_sec_ips
    virtual_server = {"name": SLB_param_data["parameters"]["virtualServerList"]["virtual-server-name"],
                      "ip-address": virtual_server_ip,
                      "port-list": virtual_server_ports}
    virtual_server_list = [virtual_server]
    data = {
        "virtual-server-list": virtual_server_list
    }
    try:
        response = requests.post(url, headers=headers,
                                 data=json.dumps(data), verify=False)

        if response.status_code != 200:
            logger.error("Failed to configure virtual server " +
                         SLB_param_data["parameters"]["virtualServerList"]["virtual-server-name"])
            logger.error(response.text)
        else:
            logger.info("Configured virtual servers")
            print("Successfully configured virtual servers.")
    except Exception as e:
        logger.error('Error in configuring virtual servers: ', exc_info=True)


def write_memory(base_url, authorization_token):
    """
    Function to save configurations on active partition
    :param base_url: Base url of AXAPI
    :param authorization_token: authorization token
    :return:
    AXAPI: /axapi/v3/active-partition
    AXAPI: /axapi/v3//write/memory
    """
    headers = {
        "Authorization": "".join(["A10 ", authorization_token]),
        "accept": "application/json",
        "Content-Type": "application/json"
    }
    url = "".join([base_url, "/active-partition"])

    response = requests.get(url, headers=headers, verify=False)
    partition = json.loads(response.text)['active-partition']['partition-name']

    if partition is None:
        print("Failed to get partition name")
        logger.error("Failed to get partition name")
    else:
        url = "".join([base_url, "/write/memory"])
        data = {
            "memory": {
                "partition": partition
            }
        }
        try:
            response = requests.post(url, headers=headers,
                                     data=json.dumps(data), verify=False)
            if response.status_code != 200:
                logger.error("Failed to run write memory command")
                print("Failed to run write memory command")
            else:
                logger.info("Configurations are saved on partition: " + partition)
                print("Configurations are saved on partition: " + partition)
        except Exception as e:
            logger.error('Error in writing to memory : ', exc_info=True)


# ------------------------------- driver code ----------------------
if __name__ == "__main__":

    # Validate and load parameter file data
    SLB_param_data = validate_load_json()
    # get public Ip of vThunder Instances
    data_interface_count = SLB_param_data["parameters"]["data_interface_count"]

    if data_interface_count == 2:
        vThunder1_addresses = SLB_param_data["parameters"]["vthunder1-address-list"]
        vThunder2_addresses = SLB_param_data["parameters"]["vthunder2-address-list"]
    else:
        vThunder1_addresses = SLB_param_data["parameters"]["vthunder1-address-list"]

    public_ip = SLB_param_data["parameters"]["publicIpList"]
    public_ip_list = []
    for ip in public_ip:
        j = ip.replace(' ', '')
        public_ip_list.append(j)

    vThunder1_sec_ips = SLB_param_data["parameters"]["virtualServerList"]["eth1-ip-address"]
    for vth in range(len(public_ip_list)):
        username = "admin"
        base_url = "https://" + public_ip_list[vth] + "/axapi/v3"
        vth_password = getpass.getpass(prompt="Enter vThunder [%s] "
                                              "Password:" % public_ip_list[vth])
        authorization_token = get_auth_token(username, vth_password, base_url)
        if authorization_token:
            # SLB configuration
            # 1. Invoke configure_ethernet
            if data_interface_count == 1:
                configure_ethernets(base_url, authorization_token, vThunder1_addresses, data_interface_count)
            else:
                if vth == 0:
                    configure_ethernets(base_url, authorization_token, vThunder1_addresses, data_interface_count)
                else:
                    configure_ethernets(base_url, authorization_token, vThunder2_addresses, data_interface_count)
            # configure empty service group
            configure_service_group(SLB_param_data, base_url, authorization_token)
            question = 'Do you want to configure SLB Server? [yes/no]'
            while True:
                user_input = input(question)
                if user_input.lower() == "yes":
                    server_configure = True
                    break
                elif user_input.lower() == "no":
                    server_configure = False
                    break
                else:
                    print("Please select correct input.")
            virtual_server_ports = SLB_param_data["parameters"]["virtualServerList"]["value"]
            if server_configure:
                # get slb server's private IP
                server_name_list = SLB_param_data["parameters"]["server_details"]["value"]
                server_name = [sub['server-name'] for sub in server_name_list]
                server_pvt_ip_list = [sub['pvt-ip-address'] for sub in server_name_list]

                # 1. Invoke configure_server
                configure_server(SLB_param_data, base_url, authorization_token, server_pvt_ip_list, server_name)

            enable_http = SLB_param_data["parameters"]["template-http"]
            # configure http template
            if enable_http == 1:
                http_list = SLB_param_data["parameters"]["httpList"]["value"]
                http_template = HTTP_TEMPLATE.VThunderHttpTemplateHandler(username)
                status = http_template.configure_http_template(public_ip_list[vth], http_list, vth_password)
                if status:
                    print("Successfully configured http template.")
                else:
                    print("Failed to configure http template.")
            else:
                for item in virtual_server_ports:
                    if "template-http" in item:
                        del item["template-http"]
            # configure persist cookie
            enable_persist_cookiee = SLB_param_data["parameters"]["template-persist-cookie"]
            if enable_persist_cookiee == 1:
                cookie_data = SLB_param_data["parameters"]["cookie-list"]["value"]
                persist_cookiee = PERSIST_COOKIE.VThunderPersistCookieHandler(username)
                status = persist_cookiee.configure_slb_persist_cookie(public_ip_list[vth], vth_password, cookie_data)
                if status:
                    print("Successfully configured slb persist cookie.")
                else:
                    print("Failed to configure slb persist cookie.")

            else:
                for item in virtual_server_ports:
                    if "template-persist-cookie" in item:
                        del item["template-persist-cookie"]
            # 4. Invoke configure_virtual_server
            configure_virtual_server(SLB_param_data, base_url, authorization_token, vThunder1_sec_ips,
                                     virtual_server_ports)
            # 5. Invoke write_memory
            write_memory(base_url, authorization_token)
            # 6. Logout from current session
            vth_logout(base_url, authorization_token)
            print(
                "--------------------------------------------------------------------------------------------------------------------")
        else:
            print("Fails to get authorization token.")
