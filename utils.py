import toml
import subprocess
import requests
import os
from lxml import etree
import logging


logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


file_handler = logging.FileHandler('app.log')
file_handler.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
file_handler.setFormatter(formatter)

logging.getLogger().addHandler(file_handler)


class Config:
    def __init__(self):
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
    def __init__(self):
        super().__init__()
        self.logger = logging.getLogger(__name__ + '.Ipam')
        
    def get_prefix(self):
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
        endpoint = self.url + "/api/ipam/ip-addresses/"
        for host in hosts_list:
            body = {
                "address": f"{host['address']}/{host['subnet']}",
                "status": "active",
                "description": "test",
                "custom_fields": {
                    "osmatch": host["os_name"]
                    }
                }
            res = requests.post(endpoint, json=body, headers=self.headers)


class NmapScript(Config):
    def __init__(self):
        super().__init__()

    def run(self, prefix_list):
        scans_list = []
        for prefix in prefix_list:
            print(f"Scanning: {prefix}")
            result = subprocess.run([self.nmap_script, prefix], capture_output=True, text=True)
            self.logger.info(f"Result: {result}")
            if result.returncode == 0:
                scans_list.append(prefix)
        self.logger.info(f"Scans completed: {scans_list}")
        return scans_list

    def count_xml(self):
        dirname = "./scans/"
        files = [os.path.join(dirname, file) for file in os.listdir(dirname) if file.endswith(".xml")]
        return files
    
    def parser_xml(self):
        files = self.count_xml()
        hosts_list = []
        self.logger.info(f"Parseando")
        for file_xml in files:
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
        result = subprocess.run(["./compress.sh"], capture_output=True, text=True) 
        return result.returncode

