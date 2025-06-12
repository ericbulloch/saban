import argparse
from ftplib import FTP
import os
from subprocess import call
from xml.etree import ElementTree


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
    minimal_space = 3    # I like having at least 3 spaces between the ip address and domain name
    spacing = minimal_space + (ipv4_max_length - len(ip_address))
    expected_line = f'{ip_address}{" " * spacing}{domain_name}'
    if expected_line in lines:
        print(f'"{expected_line}" is already in {file_name} file')
        return
    print(f'Adding "{expected_line}" to {file_name}')
    with open(file_name, 'a') as fp:
        fp.write(f'{expected_line}\n')


@step_logging(text='Running inital nmap scan')
def initial_nmap_scan(host):
    command = f'nmap -p- -T5 -Pn -v0 {host} -oX initial_nmap.xml -oN initial_nmap.txt'
    call(command, shell=True)
    print('nmap output available in initial_nmap.txt')


@step_logging(text='Running second nmap scan')
def second_nmap_scan(host):
    initial = 'initial_nmap.xml'
    tree = ElementTree.parse(initial)
    root = tree.getroot()
    ports = [p.get('portid') for p in root.find('host').find('ports').findall('port')]
    output = 'second_nmap'
    command = f'nmap -p {",".join(ports)} -A -Pn -v0 {host} -oX {output}.xml -oN {output}.txt'
    call(command, shell=True)
    print(f'nmap output available in {output}.txt')
    tree = ElementTree.parse(f'{output}.xml')
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
        print('Anonymous login successful. Here files on the ftp server:')
        for file in files:
            print(file)
    except Exception:
        pass


def ssh_handler(host, service):
    port = service.get('port')
    print(f'ssh_handler called for port {port}')


def website_handler(host, service):
    protocol = service.get('service')
    port = service.get('port')
    base_url = f'{protocol}://{host}:{port}'
    print(f'Running directory enumeration on {base_url}')
    command = f'ffuf -u {base_url}/FUZZ -w /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt -r -e .txt,.zip,.py,.php -D'
    call(command, shell=True)
    # command = f'ffuf -H "Host: FUZZ.{host}" -H "User-Agent: PENTEST" -w /usr/share/wordlists/SecLists/Discovery/Web-Content/raft-large-directories-lowercase.txt -u {base_url} -fs 100'
    # call(command, shell=True)


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
    initial_nmap_scan(args.host)
    services = second_nmap_scan(args.host)
    for service in services:
        handle(args.host, service)


service_mapping = {
    'http': website_handler,
    'https': website_handler,
    'ftp': ftp_handler,
    'ssh': ssh_handler,
}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="A script to automate some repetitive cyber security tasks")
    parser.add_argument("ip_address", help="The ip address of the capture the flag machine")
    parser.add_argument("--host", help="The host name for the capture the flag machine", default="target.thm")
    args = parser.parse_args()
    main(args)
