"""Create only the dedicated VM bridge; do not touch physical interfaces."""
import ipaddress
import json
import pathlib
import subprocess


def run(args, check=True):
    return subprocess.run(args, capture_output=True, text=True, check=check)


def main():
    routes = json.loads(run(['ip', '-j', '-4', 'route', 'show', 'table', 'all']).stdout)
    wanted = ipaddress.ip_network('172.30.61.0/30')
    for route in routes:
        dst = route.get('dst', 'default')
        if dst == 'default' or route.get('dev') == 'winbr01':
            continue
        if ipaddress.ip_network(dst, strict=False).overlaps(wanted):
            raise RuntimeError('Dedicated VM subnet conflicts with existing route')
    link = run(['ip', '-j', '-d', 'link', 'show', 'dev', 'winbr01'], check=False)
    if link.returncode:
        run(['ip', 'link', 'add', 'name', 'winbr01', 'type', 'bridge'])
    elif json.loads(link.stdout)[0].get('linkinfo', {}).get('info_kind') != 'bridge':
        raise RuntimeError('Existing winbr01 is not a bridge')
    ports = json.loads(run(['ip', '-j', '-d', 'link', 'show', 'master', 'winbr01']).stdout)
    if any(p.get('linkinfo', {}).get('info_kind') != 'tun' for p in ports):
        raise RuntimeError('VM bridge has a non-tap port; refusing configuration')
    addresses = json.loads(run(['ip', '-j', '-4', 'addr', 'show', 'dev', 'winbr01']).stdout)
    for addr in (addresses[0].get('addr_info', []) if addresses else []):
        if addr['local'] != '172.30.61.1' or addr['prefixlen'] != 30:
            raise RuntimeError('Existing bridge has unexpected IPv4 configuration')
    run(['ip', 'addr', 'replace', '172.30.61.1/30', 'dev', 'winbr01'])
    pathlib.Path('/proc/sys/net/ipv6/conf/winbr01/disable_ipv6').write_text('1')
    # Only this bridge permits localhost DNAT replies; global routing stays unchanged.
    pathlib.Path('/proc/sys/net/ipv4/conf/winbr01/route_localnet').write_text('1')
    run(['ip', 'link', 'set', 'dev', 'winbr01', 'up'])
    print('Dedicated bridge ready: winbr01, 172.30.61.1/30, no physical ports')


if __name__ == '__main__':
    main()
