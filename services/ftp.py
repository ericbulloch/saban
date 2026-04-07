from ftplib import error_perm, FTP


def grab_banner(ftp):
    banner = ftp.getwelcome()
    return banner


def try_login(ftp, username, password):
    success = False
    try:
        ftp.login(user=username, passwd=password)
        success = True
        ftp.quit()
    except error_perm:
        pass
    return success


def walk(ftp, path='/', results=None):
    if results is None:
        results = []

    original_dir = ftp.pwd()
    try:
        ftp.pwd(path)
    except error_perm:
        return results

    try:
        for name, facts in ftp.mlsd():
            item_path = f'{path}/{name}'.replace('//', '/')
            results.append(item_path)

            if facts.get('type') == 'dir':
                walk(ftp, item_path, results)
    except error_perm:
        listing = []
        ftp.retrlines('LIST', listing.append)
        for line in listing:
            parts = line.split()
            name = parts[-1]
            is_dir = line.lower().startswith('d')
            item_path = f'{path}/{name}'.replace('//', '/')
            results.append(item_path)
            if is_dir:
                walk(ftp, item_path, results)

    ftp.cwd(original_dir)
    return results


def pillage(ftp, username, password):
    pass


def main(host, port):
    ftp = FTP()
    ftp.connect(host=host, port=port)
    banner = grab_banner(ftp)
    print(f'Banner: {banner}')
    if try_login(ftp, 'anonymous', 'anonymous'):
        print('anonymous login allowed')
    ftp.close()
    # pillage
