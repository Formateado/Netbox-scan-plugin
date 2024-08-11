import toml
import subprocess
import requests
import os
from lxml import etree
import logging

# Configure logging to display info and error messages
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

file_handler = logging.FileHandler('scan.log')
file_handler.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
file_handler.setFormatter(formatter)

logging.getLogger().addHandler(file_handler)

class Config:
    def __init__(self):
        """
        Initializes the configuration by loading the TOML file and setting up required variables.
        """
        config_file = "config.toml"
        with open(config_file, 'r') as f:
            config = toml.load(f)
        
        self.url = config['api']['url_base']
        token = config['api']['token']
        self.nmap_script = config['nmap_script']['script_name']
        
        self.headers = {
            'accept': 'application/json',
            'Authorization': f'Token {token}'
        }
        self.logger = logging.getLogger(__name__)

class Ipam(Config):
    """
    Interacts with the IPAM API to retrieve prefixes and publish active IP addresses (ICMP PROTOCOL) on netbox.
    """
    def __init__(self):
        super().__init__()
        self.logger = logging.getLogger(__name__ + '.Ipam')

    def get_prefix(self):
        """
        Retrieves a list of prefixes from the IPAM API that have the 'Discover' tag.

        Returns:
            list: A list of prefixes with the 'Discover' tag.
        """
        endpoint = self.url + "/api/ipam/prefixes/"
        res = requests.get(endpoint, headers=self.headers).json()
        prefix_list = []
        results = res["results"]
        for result in results:
            if any(tag['name'] == 'Discover' for tag in result['tags']):
                prefix_list.append(result['prefix'])
        self.logger.info(f"Prefix list retrieved: {prefix_list}")

        return prefix_list

    def post_ipaddress(self, hosts_list):
        """
        Posts a list of IP addresses to the IPAM API.

        Args:
            hosts_list (list): A list of dictionaries containing IP address and subnet information.
        """
        endpoint = self.url + "/api/ipam/ip-addresses/"
        for host in hosts_list:
            body = {
                "address": f"{host['address']}/{host['subnet']}",
                "status": "active",
                "description": "Automatic scanning",
                "custom_fields": {
                    "osmatch": host["os_name"]
                }
            }
            res = requests.post(endpoint, json=body, headers=self.headers)

class NmapScript(Config):
    """
    Runs an Nmap script, processes XML results, and compresses them into tar.gz.
    """
    def __init__(self):
        super().__init__()

    def run(self, prefix_list):
        """
        Runs Nmap scans for each prefix in the provided list.

        Args:
            prefix_list (list): A list of prefixes to scan.

        Returns:
            list: A list of prefixes that were successfully scanned.
        """
        scans_list = []
        for prefix in prefix_list:
            self.logger.info(f"Scanning: {prefix}")
            result = subprocess.run([self.nmap_script, prefix], capture_output=True, text=True)
            if result.returncode == 0:
                scans_list.append(prefix)
        self.logger.info(f"Scans completed: {scans_list}")
        return scans_list

    def count_xml(self):
        """
        Counts and lists XML files in the scans directory.

        Returns:
            list: A list of paths to XML files.
        """
        dirname = "./scans/"
        files = [os.path.join(dirname, file) for file in os.listdir(dirname) if file.endswith(".xml")]
        return files
    
    def parser_xml(self):
        """
        Parses XML files to extract host information.

        Returns:
            list: A list of dictionaries containing host information.
        """
        files = self.count_xml()
        hosts_list = []
        self.logger.info(f"Parsing XML files")
        for file_xml in files:
            #add try
            subnet_slice = file_xml[-6:-4]
            tree = etree.parse(file_xml)
            root = tree.getroot()

            for host in root.findall('.//host'):
                host_dict = {}
                host_dict['address'] = host.find('address').attrib['addr']
                host_dict['subnet'] = f"{subnet_slice}"

                osmatches = host.findall('.//os/osmatch')
                if osmatches:
                    name = osmatches[0].attrib['name']
                    accuracy = osmatches[0].attrib['accuracy']
                    host_dict['os_name'] = f"Os: {name}, Accuracy: {accuracy}"
                else:
                    host_dict['os_name'] = "OS not detected"

                hosts_list.append(host_dict)

        return hosts_list

    def compress(self):
        """
        Runs a shell script to compress files.

        Returns:
            int: The return code of the shell script.
        """
        result = subprocess.run(["./compress.sh"], capture_output=True, text=True) 
        return result.returncode

