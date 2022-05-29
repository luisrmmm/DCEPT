import yaml
import logging
import os


class ConfigError(Exception):
    pass


class Config:
    def __init__(self, file_path):
        try:
            with open(file_path, 'r') as f:
                config_yaml = yaml.safe_load(f)
        except Exception as e:
            logging.error(e)
            raise ConfigError(f'Error reading config file')

        # aplication config
        self.master_node = config_yaml.get('master_node', None)
        self.honeytoken_host = config_yaml.get('honeytoken_host', '0.0.0.0')
        self.honeytoken_param_name = config_yaml.get('honeytoken_param_name', 'machine')
        self.honeytoken_uri = config_yaml.get('honeytoken_uri', '/honeyuri')
        self.honeytoken_port = config_yaml.get('honeytoken_port', 8080)
        self.interface = config_yaml.get('interface', None)
        self.domain = config_yaml.get('domain', None)
        self.realm = config_yaml.get('realm', None)
        self.honey_username = config_yaml.get('honey_username', None)
        self.sqlite_path = config_yaml.get('sqlite_path', 'sqlite3db.db')
        self.john_path = config_yaml.get('john_path', 'john')

        # alert config
        self.smtp_host = config_yaml.get('smtp_host', None)
        self.smtp_port = config_yaml.get('smtp_port', 25)
        self.email_address = config_yaml.get('email_address', None)
        self.subject = config_yaml.get('subject', 'DCEPT Triggered - Immediate Action Necessary')
        self.syslog_host = config_yaml.get('syslog_host', None)
        self.syslog_port = config_yaml.get('syslog_port', 514)
        self.file_path = config_yaml.get('file_path', None)

        # log level
        self.log_level = config_yaml.get('log_level', 'INFO')

        self.check_config()

    def check_config(self):
        if not self.interface:
            raise ConfigError("You must configure an interface")

        if not self.domain:
            raise ConfigError("You must configure a domain")

        if not self.realm:
            raise ConfigError("You must configure a realm")

        if not self.honey_username:
            raise ConfigError("You must configure a honeytoken username")

        if not os.path.exists(self.john_path):
            raise ConfigError("John the Ripper does not exists on the configured path")

        if self.file_path:
            if not os.path.exists(os.path.dirname(self.file_path)):
                logging.info(f'Creating {os.path.dirname(self.file_path)} for alerts file')
                os.makedirs(os.path.dirname(self.file_path))

        if self.log_level.upper() not in {"CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG", "NOTSET"}:
            raise ConfigError("Invalid setting for log level")
        else:
            level = logging.getLevelName(self.log_level.upper())
            logging.getLogger().setLevel(level)
