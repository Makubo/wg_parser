#!/usr/bin/env python3
# Usage:
# ./wg_parser.py <first_argument> [second_argument]
# First argument - xml configuration path
# Second argument - csv output file path
# If second argument is not exist, output will be to stdout

import sys
import xml.etree.ElementTree as ET
from netaddr import IPAddress

file = sys.argv[1]
if len(sys.argv) >= 3:
    csv = sys.argv[2]
    sys.stdout = open(csv, "w+")
config = ET.parse(file)
root = config.getroot()

def my_append(x, y):
    if len(x) == 0:
        x = y
    else:
        x = x + ', ' + y
    return x

def find_alias(name):
    for alias in root.find('alias-list').findall('alias'):
        if alias.find('name').text == name:
            ret = alias
    return ret

def find_address(name):
    ret = 'find_address_ERROR'
    if name == 'Firebox':
        return name
    for group in root.find('address-group-list').findall('address-group'):
        if group.find('name').text == name:
            member = group.find('addr-group-member').find('member')
            if member.find('type').text == '1':
                ret = member.find('host-ip-addr').text 
            if member.find('type').text == '2':
                ret = member.find('ip-network-addr').text + '/' + str(IPAddress(member.find('ip-mask').text).netmask_bits())
            if member.find('type').text == '3':
                ret = member.find('start-ip-addr').text + '-' + member.find('end-ip-addr').text
    return ret

def get_nat(name):
    for nat in root.find('nat-list').findall('nat'):
        if nat.find('name').text == name:
            return nat
        
def get_nat_string(nat):
    ret = ''
    for member in nat.find('nat-item').findall('member'):
        if nat.find('type').text == '4':
            ret = my_append(ret, member.find('ip').text)
        if nat.find('type').text == '7':
            if member.find('port').text == '0':
                ret = my_append(ret, find_address(member.find('ext-addr-name').text) + ' --> ' + find_address(member.find('addr-name').text))
            if member.find('port').text != '0':
                ret = my_append(ret, find_address(member.find('ext-addr-name').text) + ' --> ' + find_address(member.find('addr-name').text) + " : " + member.find('port').text)
    return ret

def get_service(name):
    for service in root.find('service-list').findall('service'):
        if service.find('name').text == name:
            return service

def get_service_ports(member):
    ret = 'get_service_ports_ERROR'
    if member.find('type').text == '1':
        ret = member.find('server-port').text
        if member.find('server-port').text == '0':
            ret = ret + ' (Any)'
    if member.find('type').text == '2':
        ret = member.find('start-server-port').text + '-' + member.find('end-server-port').text
    return ret

def get_service_icmp(member):
    ret = 'get_service_icmp_ERROR'
    if member.find('type').text == '1':
        ret = 'ICMP(type: ' + member.find('icmp-type').text + ', code: ' + member.find('icmp-code').text + ')'
    #if member.find('type').text == '2':
        #I didn't have a config examples for that case
    return ret

def get_service_string(service):
    ret = ''
    for member in service.find('service-item').findall('member'):
        if member.find('protocol').text == '0':
            ret = my_append(ret, 'Any')
        if member.find('protocol').text == '1':
            ret = my_append(ret, get_service_icmp(member))
        if member.find('protocol').text == '6':
            ret = my_append(ret, 'tcp:' + get_service_ports(member))
        if member.find('protocol').text == '17':
            ret = my_append(ret, 'udp:' + get_service_ports(member))
    return ret

print('#', 'Action', 'Enabled', 'Policy Name', 'From', 'To', 'Port', sep=';')

policyNumber = 0
for policy in root.find('abs-policy-list').findall('abs-policy'):
    policyName = policy.find('name').text
    policyAction = policy.find('firewall').text
    policyEnabled = policy.find('enabled').text
    policyService = policy.find('service').text
    policyService = get_service_string(get_service(policy.find('service').text))

    # It was a mind flow. I'm deeply sorry https://youtu.be/WTsDqIcpHUc
    fr = ""
    for alias in policy.find('from-alias-list').findall('alias'):
        for alias2 in root.find('alias-list').findall('alias'):
            if alias2.find('name').text == alias.text:
                for alias3 in alias2.find('alias-member-list').findall('alias-member'):
                    if alias3.find('type').text == '2':
                        fr = my_append(fr, alias3.find('alias-name').text)
                    else:
                        if alias3.find('address').text == "Any" and alias3.find('user').text != "Any":
                            for group in root.find('auth-group-list').findall('auth-group'):
                                if group.find('name').text == alias3.find('user').text:
                                    groupItem = group.find('auth-group-item').find('item')
                                    if groupItem.find('type').text == '2':
                                        fr = my_append(fr, groupItem.find('membership-id').text + '(' + groupItem.find('auth-domain').text + ')')
                                    else:
                                        fr = my_append(fr, groupItem.find('user-id').text + '(' + groupItem.find('auth-domain').text + ')')
                        if alias3.find('address').text != "Any" and alias3.find('user').text == "Any":
                            for group in root.find('address-group-list').findall('address-group'):
                                if group.find('name').text == alias3.find('address').text:
                                    groupMember = group.find('addr-group-member').find('member')
                                    if groupMember.find('type').text == '1':
                                        fr = my_append(fr, groupMember.find('host-ip-addr').text)
                                    else:
                                        fr = my_append(fr, groupMember.find('ip-network-addr').text + '/' + str(IPAddress(groupMember.find('ip-mask').text).netmask_bits()))
                        if alias3.find('address').text == "Any" and alias3.find('user').text == "Any":
                            fr = my_append(fr, alias3.find('interface').text)
    to = ""
    if not policy.find('policy-nat').text:
        for alias in policy.find('to-alias-list').findall('alias'):
            for alias2 in root.find('alias-list').findall('alias'):
                if alias2.find('name').text == alias.text:
                    for alias3 in alias2.find('alias-member-list').findall('alias-member'):
                        if alias3.find('type').text == '2':
                            alias4 = find_alias(alias3.find('alias-name').text)
                            if alias4 is not None:
                                for member2 in alias4.find('alias-member-list').findall('alias-member'):
                                    if member2.find('type').text != '2':
                                        if member2.find('user').text != 'Any' and member2.find('address').text == 'Any':
                                            to = my_append(to, member2.find('user').text)
                                        if member2.find('user').text == 'Any' and member2.find('address').text != 'Any':
                                            address = find_address(member2.find('address').text)
                                            to = my_append(to, address)
                                        if member2.find('user').text == 'Any' and member2.find('address').text == 'Any':
                                            to = my_append(to, member2.find('interface').text)
                                    else:
                                        to = my_append(to, alias4.find('name').text)
                            else:
                                to = my_append(to, 'null')
                        else:
                            if alias3.find('address').text == "Any" and alias3.find('user').text != "Any":
                                for group in root.find('auth-group-list').findall('auth-group'):
                                    if group.find('name').text == alias3.find('user').text:
                                        groupItem = group.find('auth-group-item').find('item')
                                        if groupItem.find('type').text == '2':
                                            to = my_append(to, groupItem.find('membership-id').text + '(' + groupItem.find('auth-domain').text + ')')
                                        else:
                                            to = my_append(to, groupItem.find('user-id').text + '(' + groupItem.find('auth-domain').text + ')')
                            if alias3.find('address').text != "Any" and alias3.find('user').text == "Any":
                                for group in root.find('address-group-list').findall('address-group'):
                                    if group.find('name').text == alias3.find('address').text:
                                        groupMember = group.find('addr-group-member').find('member')
                                        if groupMember.find('type').text == '1':
                                            to = my_append(to, groupMember.find('host-ip-addr').text)
                                        if groupMember.find('type').text == '2':    
                                            to = my_append(to, groupMember.find('ip-network-addr').text + '/' + str(IPAddress(groupMember.find('ip-mask').text).netmask_bits()) )
                                        if groupMember.find('type').text == '3':
                                            to = my_append(to, alias.text)

                            if alias3.find('address').text == "Any" and alias3.find('user').text == "Any":
                                to = my_append(to, alias3.find('interface').text)
    if policy.find('policy-nat').text:
        nat = get_nat(policy.find('policy-nat').text)
        to = my_append(to,get_nat_string(nat))
        
    print(policyNumber, policyAction, policyEnabled, policyName, fr, to, policyService, sep=';')
    policyNumber = policyNumber + 1