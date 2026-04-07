from ftplib import FTP


def grab_banner(ftp):
    banner = ftp.getwelcome()
    return banner


def main(host, port):
    # grab banner
    # try anonymous login
    # try login
    # pillage
