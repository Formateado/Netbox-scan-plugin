# Automatic Scanner Plugin for NetBox

This plugin gets pre-loaded prefixes from NetBox and performs scans with Nmap

## How to install

### Clone the repository

```bash
git clone https://github.com/Formateado/Netbox-scan-plugin.git
```
```bash
cd Netbox-scan-plugin
```

### Install dependencies
```bash
pip3 install -r requirements.txt
```
```bash
sudo apt install nmap
```
### Edit the config.toml file
```
# Example
url_base = "http://127.0.0.1:8000/"
token = "1273qwed13123deqe12314"
```
### Run setup.py (coming soon)
```bash
python3 setup.py 
```
## How to use
Go to NetBox, load the prefixes you want to scan and add the `Discover` tag to them.
Run the script with `sudo` or as `root`, it will display the logs on screen (it will also save them in a scan.log file).

When the script finishes the active IPs are loaded in the IPAM -> IP Addresses section, you can also configure the table to add the custom `osmatch` column.
Each scan will be saved in the plugin's scans folder, compressed in `tar.gz` format with each corresponding prefix in `.xml` format.
