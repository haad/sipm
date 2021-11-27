# vi: ft=python

import argparse
import ipaddress
import netaddr
import logging
import yaml

from pprint import pprint

IPDB_PATH='/tmp/ip.db.yaml'

class IPmanager:
    def __init__(self, db_path=IPDB_PATH):
        self.db=IPDB_PATH
        self.config = self._load_db(db_path)

        logging.basicConfig(level=logging.WARNING)

    def return_ip(self, ip):
        logging.debug("Returning ip {} to the pool".format(ip))
        self._remove_leased_ip(ip)

    def get_ip(self, group):
        logging.debug("Getting next available IP")

        used_ips = self._get_leased_ips_for_group(group)
        subnet = ipaddress.ip_network(self._get_subnet_for_group(group))

        for host in subnet.hosts():
#            logging.debug("IP: {}, is already leased, {}".format(host, used_ips))

            if str(host) in used_ips:
                logging.debug("IP: {}, is already leased, {}".format(host, used_ips))
            else:
                logging.debug("IP: {}, leased.".format(host))

                self.config['leases'].append(str(host))
                self.config['leases'].sort()

                self._save_db(self.db)

                return host

    def list_ips(self, group=None):
        if group != None:
            logging.info("List ips by group: {}".format(group))
            [print(i) for i in self._get_leased_ips_for_group(group)]
        else:
            logging.info("List leased IPS")
            [print(i) for i in self.config.get('leases', [])]

    def list_groups(self):
        [print("Group: {}, Subnet: {}".format(i['name'], i['subnet'])) for i in self.config.get('config', {}).get('groups', [])]

    def iptables_rule(self, interface):
        groups = self.config.get('config', {}).get('groups', [])
        for group in groups:
            name = group['name']
            subnet = group['subnet']

            print('iptables -A PREROUTING -i {int} -t mangle -s {subnet} -j MARK --set-mark {index}'.format(int=interface, subnet=subnet, index=(groups.index(group) + 1)))

    def _remove_leased_ip(self, ip):
        ips = self.config.get('leases', [])

        try:
            ips.index(ip)
        except ValueError:
            logging.info("IP {} not in the list".format(ip))
            return

        ips.remove(ip)


    def _get_leased_ips_for_group(self, group_name):
        ips = []
        subnet = self._get_subnet_for_group(group_name)

        for ip in self.config.get('leases', []):
            if ipaddress.ip_address(ip) in ipaddress.ip_network(subnet):
                ips.append(ip)
        return ips

    def _get_subnet_for_group(self, group_name):
        for group in self.config.get('config', {}).get('groups', []):
            if group.get('name', '') == group_name:
                return group['subnet']

    def _load_db(self, db):
        config = None

        with open(db, "r") as stream:
            try:
                config = yaml.safe_load(stream)
            except yaml.YAMLError as exc:
                print(exc)

        return config

    def _save_db(self, db):
        with open(db, 'w') as yaml_file:
            print(yaml.dump(self.config))
            yaml.dump(self.config, yaml_file, default_flow_style=False)



parser = argparse.ArgumentParser(description='Add some integers.')

parser.add_argument('-G', '--get_ip', action='store', type=str)
parser.add_argument('-R', '--return_ip', action='store', type=str)
parser.add_argument('-I', '--iptables_rule', action='store', type=str)
parser.add_argument('-l', '--list', action='store_true' )
parser.add_argument('-L', '--list_groups', action='store_true' )

args = parser.parse_args()
ipm = IPmanager()

# print(vars(args))

if args.get_ip:
    ipm.get_ip(args.get_ip)

if args.return_ip:
    ipm.return_ip(args.return_ip)

if args.iptables_rule:
    ipm.iptables_rule(args.iptables_rule)

if args.list:
    ipm.list_ips()

if args.list_groups:
    ipm.list_groups()

# ipm.get_ip('DEV')
# ipm.get_ip('ADMIN')

# print('=========================')
# ipm.list_ips()
# print('=========================')
# ipm.list_ips('DEV')
# print('=========================')
# ipm.list_ips('ADMIN')
# print('=========================')
# ipm.return_ip('10.1.14.67')
# ipm.return_ip('10.1.14.99')
# print('=========================')
# ipm.list_ips('DEV')
# print('=========================')
# ipm.list_ips('ADMIN')

# ipm.iptables_rule('wg0')
