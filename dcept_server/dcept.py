import logging
from config_reader import Config, ConfigError
import pyiface
from generation_server import GenerationServer
from threading import Thread
from api_server import APIServer
from cracker import Cracker
from sniffer import kerbsniff
import sys
import requests



class DceptError(Exception):
    def __init__(self, message=''):
        Exception.__init__(self, message)


def test_interface(interface):
    try:
        iface = pyiface.Interface(name=interface)
        if iface.flags == iface.flags | pyiface.IFF_UP:
            return True
    except IOError as e:
        if e.errno == 19:  # No such device
            print(f"Bad interface. No such device '{interface}'")
    return False


def main():
    banner = """
      _____   _____ ______ _____ _______ 
     |  __ \\ / ____|  ____|  __ |__   __|
     | |  | | |    | |__  | |__) | | |   
     | |  | | |    |  __| |  ___/  | |   
     | |__| | |____| |____| |      | |   
     |_____/ \\_____|______|_|      |_|
    """

    print(banner)

    try:
        # Read the configuration file
        config = Config('config.yaml')
    except ConfigError as e:
        logging.error(e)
        raise DceptError()

    # Server roles for multi-server topology
    if not config.master_node:
        logging.info('Server configured as master node')
    else:
        logging.info('Server configured as slave node')

    # Sanity check - Check if the interface is up
    if not test_interface(config.interface):
        logging.error(f"Unable to listen on '{config.interface}'. Is the interface up?")
        raise DceptError()

    logging.info('Starting DCEPT...')

    if not config.master_node:  # (Master Node)

        # Spawn and start the password generation server
        gen_server = GenerationServer(config)
        logging.info('Started generation server')

        # Initialize the cracker
        cracker = Cracker(config, gen_server)
        Thread(target=cracker.run, daemon=True).start()
        logging.info('Started Cracker in a new daemon thread')

        # Start the webserver on its own thread.
        api_server = APIServer(config, gen_server, cracker)
        Thread(target=api_server.run, daemon=True).start()
        logging.info('Started honeytoken API server in a new daemon thread')

    else:  # (Slave Node)
        # Test Connection to master node
        try:
            requests.post(f"http://{config.master_node}:{config.honeytoken_port}/notify")
        except (requests.exceptions.Timeout, requests.exceptions.ConnectionError) as e:
            logging.error('Error connecting to master node')
            logging.error(e)
            raise DceptError()
        cracker = None

    # Start the sniffer (Both master and slave)
    logging.info('Starting sniffer')
    kerbsniff(config, cracker)


if __name__ == '__main__':

    try:
        # Setup logging to file for troubleshooting
        # logging.basicConfig(filename='dcept.log', format='%(asctime)s %(levelname)s %(message)s')
        # Mirror logging to console
        # logging.getLogger().addHandler(logging.StreamHandler())
        # logging.basicConfig(filename='example.log', encoding='utf-8', level=logging.DEBUG)
        logging.basicConfig(level=logging.DEBUG,
                            format='%(asctime)s %(levelname)s %(message)s',
                            handlers=[logging.FileHandler('dcept.log'), logging.StreamHandler(sys.stdout)])

        main()
    except (KeyboardInterrupt, DceptError):
        logging.info("Shutting down DCEPT...")
