from ftplib import FTP


def grab_banner(host, port):
    ftp = FTP()
    ftp.connect(host=host, port=port)
