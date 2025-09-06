import argparse
from ftplib import FTP
import os
import re
import subprocess
from subprocess import call
from xml.etree import ElementTree

import paramiko
import requests


def step_logging(text):
    def decorator(func):
        def wrapper(*args, **kwargs):
            print(f'{text}...')
            output = func(*args, **kwargs)
            print(f'Done {text[0].lower() + text[1:]}.')
            print('\n')
            return output
        return wrapper
    return decorator


@step_logging(text='Checking effective user id of this process')
def check_effective_user():
    if os.geteuid() != 0:
        print('Please run this script with elevated privileges.')
        exit(-1)


@step_logging(text='Checking if IP address needs to be added to hosts file')
def add_to_host_file(ip_address, domain_name):
    file_name = '/etc/hosts'
    with open(file_name, 'r') as fp:
        lines = [l.strip() for l in fp.readlines()]
    ipv4_max_length = 15    # 4 octets of 3 character and 3 periods between
    minimal_gap = 3    # I like having at least 3 spaces between the ip address and domain name
    spacing = minimal_gap + (ipv4_max_length - len(ip_address))
    expected_line = f'{ip_address}{" " * spacing}{domain_name}'
    if expected_line in lines:
        print(f'"{expected_line}" is already in {file_name} file')
        return
    print(f'Adding "{expected_line}" to {file_name}')
    with open(file_name, 'a') as fp:
        fp.write(f'{expected_line}\n')


@step_logging(text='Running nmap scan')
def nmap_scan(host):
    command = f'nmap -T4 -n -sC -sV -Pn -v0 -p- {host} -oX nmap.xml -oN nmap.txt'
    call(command, shell=True)
    print(f'nmap output available in nmap.txt and nmap.xml')
    tree = ElementTree.parse(f'nmap.xml')
    root = tree.getroot()
    services = []
    ports = root.find('host').find('ports').findall('port')
    for port in ports:
        number = port.get('portid')
        service = port.find('service')
        name = service.get('name')
        product = service.get('product')
        version = service.get('version')
        services.append(dict(port=number, service=name, product=product, version=version))
    return services


def ftp_handler(host, service):
    port = service.get('port')
    print(f'ftp_handler called for port {port}')
    try:
        ftp = FTP(host)
        ftp.login()
        files = ftp.nlst()
        ftp.quit()
        print('Anonymous login successful. Here are the files on the ftp server:')
        for file in files:
            print(file)
    except Exception:
        pass


def image_handler(url, destination):
    response = requests.get(url, stream=True)
    if not response.ok:
        return
    with open(destination, 'wb') as file:
        for chunk in response.iter_content(chunk_size=8192):
            file.write(chunk)
    command = f'exiftool {destination}'
    call(command, shell=True)
    command = f'binwalk -e {destination}'
    call(command, shell=True)
    command = f'steghide info {destination}'
    call(command, shell=True)


def pop3_handler(host, service):
    pass


def nfs_handler(host, service):
    pass


def smb_handler(host, service):
    port = service.get('port')
    command = ['smbmap', '-H' host]
    output = subprocess.check_output(command)
    lines = output.decode().split('\n')
    found = False
    disks = []
    for line in lines:
        line = line.strip()
        parts = [l for l in line.split(' ') if l]
        if found:
            if parts[1] == 'READ ONLY':
                disks.append(parts[0])
        else:
            length = len(parts[0]) + len(parts[1])
            if parts[0] + parts[1] == '-' * length:
                found = True
    if disks:
        print('Found the following SMB disks:')
        for disk in disks:
            print(f'{disk}, connect with the following command:')
            print(f'smbclient //{host}/{disk}/ -n \n')


def ssh_handler(host, service):
    port = service.get('port')
    print(f'ssh_handler called for port {port}')
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    username = 'does_not_exist'
    password = 'password'
    try:
        client.connect(host, port=port, username=username, password=password)
        print(f'Great news! SSH authentication worked with {username}:{password}')
    except paramiko.AuthenticationException:
        print(f'SSH password authentication is allowed for {host}')
    except paramiko.BadAuthenticationType:
        print(f'{host} requires public-key to remote in')
    client.close()


def website_handler(host, service):
    protocol = service.get('service')
    port = service.get('port')
    base_url = f'{protocol}://{host}:{port}'
    print(f'Running directory enumeration on {base_url}')
    command = f'gobuster dir -u {base_url} -w /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt -x txt,zip,php'
    call(command, shell=True)
    with open('bad_subdomains.txt', 'w') as fp:
        for subdomain in ['SHOULD_NOT_EXIST_SUBDOMAIN']:
            fp.write(f'{subdomain}\n')
    command = ['ffuf', '-H', f"Host: FUZZ.{host}", '-H', "User-Agent: PENTEST", '-w', 'bad_subdomains.txt', '-u', base_url]
    output = subprocess.check_output(command)
    regex = r"^.+ Size: (\d+)"
    match = re.match(regex, output.decode())
    if match:
        size = match.groups()[0]
        command = f'ffuf -H "Host: FUZZ.{host}" -H "User-Agent: PENTEST" -w /usr/share/wordlists/SecLists/Discovery/Web-Content/raft-large-directories-lowercase.txt -u {base_url} -fs {size}'
        call(command, shell=True)


def unhandled_service(host, service):
    port = service.get('port')
    name = service.get('service')
    product = service.get('product')
    version = service.get('version')
    print(f'Unhandled service ({name}) on port {port} running {product} version {version}')


def handle(host, service):
    port = service.get('port')
    name = service.get('service')
    product = service.get('product')
    version = service.get('version')
    print(f'Handling service ({name}) on port {port} running {product} version {version}')
    print(f'Possible searchsploit command: searchsploit {product} {version}')
    handler = service_mapping.get(service.get('service'))
    if not handler:
        unhandled_service(host, service)
    else:
        handler(host, service)


def main(args):
    check_effective_user()
    add_to_host_file(args.ip_address, args.host)
    services = nmap_scan(args.host)
    for service in services:
        handle(args.host, service)


service_mapping = {
    'ftp': ftp_handler,
    'http': website_handler,
    'https': website_handler,
    'pop3': pop3_handler,
    'nfs': nfs_handler,
    'smb': smb_handler,
    'ssh': ssh_handler,
}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="A script to automate some repetitive cyber security tasks")
    parser.add_argument("ip_address", help="The ip address of the capture the flag machine")
    parser.add_argument("--host", help="The host name for the capture the flag machine", default="target.thm")
    args = parser.parse_args()
    main(args)
