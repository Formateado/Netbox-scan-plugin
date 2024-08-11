from utils import Ipam, NmapScript


def run():
    api = Ipam()
    script = NmapScript()

    prefix_list = api.get_prefix()
    scans = script.run(prefix_list)

    if len(scans) > 0:
        data = script.parser_xml()
        api.post_ipaddress(data)
        script.compress()
        

if __name__ == '__main__':
    run()
