import toml
import subprocess
import requests
import os
from lxml import etree

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

class Ipam(Config):
    def __init__(self):
        super().__init__()
        
    def get_prefix(self):
        endpoint = self.url + "/api/ipam/prefixes/"
        res = requests.get(endpoint, headers=self.headers).json()
        results = res["results"]
        prefix_list = [data["prefix"] for data in results]
        
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
            if result.returncode == 0:
                scans_list.append(prefix)
        return scans_list

    def count_xml(self):
        dirname = "./scans/"
        files = [os.path.join(dirname, file) for file in os.listdir(dirname) if file.endswith(".xml")]
        return files
    
    def parser_xml(self):
        files = self.count_xml()
        hosts_list = []
        for file_xml in files:
            subnet_slice = file_xml[-6:-4]
            tree = etree.parse(file_xml)
            root = tree.getroot()

            for host in root.xpath('//host'):
                host_dict = {}

                address_elem = host.xpath('address[@addrtype="ipv4"]')[0]
                host_dict['address'] = address_elem.get('addr', 'Unknown')
                host_dict['subnet'] = f"{subnet_slice}"

                status_elem = host.xpath('status')[0]
                host_dict['status'] = status_elem.get('state', 'Unknown')

                os_elem = host.xpath('os/osmatch')[0]
                host_dict['os_name'] = os_elem.get('name', 'OS not detected')

                hosts_list.append(host_dict)
        return hosts_list

    def compress(self):
        result = subprocess.run(["./compress.sh"], capture_output=True, text=True) 
        return result.returncode
