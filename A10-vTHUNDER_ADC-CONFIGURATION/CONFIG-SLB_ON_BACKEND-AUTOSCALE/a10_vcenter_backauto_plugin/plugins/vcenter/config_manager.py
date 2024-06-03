#!/backautovenv/bin/python3
"""
Module to validate, load config.ini file
"""
import os
import configparser as cfg
import fcntl

class ConfigManager:
    def __init__(self, app_name):
        self.app_name = app_name
        self.config = cfg.ConfigParser()
        self.vcenter_config = cfg.ConfigParser()
        self.current_working_directory = os.path.join(os.path.dirname(os.path.dirname(
            os.path.dirname(os.path.abspath(__file__)))), 'apps', self.app_name)
        self.config_file_loc = os.path.join(self.current_working_directory, 'config.ini')
        self.app_servers_file_loc = os.path.join(self.current_working_directory, 'app_servers.ini')
        self.vcenter_config_file_loc = os.path.dirname(os.path.dirname(
            os.path.dirname(os.path.abspath(__file__))))
        self.vcenter_config_file_loc = os.path.join(self.vcenter_config_file_loc, 'vcenter.ini')
        self.config.read(self.config_file_loc)
        self.app_servers = self.read_config()
        self.vcenter_config.read(self.vcenter_config_file_loc)
        self.__validate_config(self.config)
        self.__validate_config(self.app_servers)
        self.__validate_config(self.vcenter_config)

    @staticmethod
    def __validate_config(config):
        sections = config.sections()
        for section in sections:
            # get each section values
            section_values = config.items(section)
            for item in section_values:
                # check null values
                if not config.get(section, item[0]):
                    raise Exception("key %s value not found or empty, "
                                    "fill value in config.ini file" % item[0])

    def lock_file(self):
        self.file = open(self.app_servers_file_loc, 'r+')
        fcntl.flock(self.file.fileno(), fcntl.LOCK_EX)

    def unlock_file(self):
        fcntl.flock(self.file.fileno(), fcntl.LOCK_UN)
        self.file.close()

    def read_config(self):
        try:
            self.lock_file()
            config = cfg.ConfigParser()
            config.read_file(self.file)
        finally:
            self.unlock_file()
            return config
    
    def get_configs(self):
        # if not ConfigManager.config and not ConfigManager.app_servers:
        return self.config, self.app_servers, self.vcenter_config

    def set_config(self, section, key, value):
        try:
            self.app_servers.set(section, key, value)
            self.lock_file()
            self.file.seek(0)  # Ensure we are at the beginning of the file
            self.file.truncate()  # Clear the existing content
            self.app_servers.write(self.file)
        finally:
            self.unlock_file()