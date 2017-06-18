#!/usr/local/bin/python
# vim: set fenc=utf8 ts=4 sw=4 et :
#
# Layer 2 network neighbourhood discovery tool
# written by Benedikt Waldvogel (mail at bwaldvogel.de)

from __future__ import absolute_import, division, print_function

from time import sleep

import os
import logging

import scapy.config
import scapy.layers.l2
import scapy.route
import signal
import socket
import subprocess
import math
import errno

logging.basicConfig(format='%(asctime)s %(levelname)-5s %(message)s', datefmt='%Y-%m-%d %H:%M:%S', level=logging.DEBUG)
logger = logging.getLogger(__name__)

MAC_ADDRESSES = [
    '30:75:12:f1:be:e8'  # Javier's phone
]
RETRIES = 5
SLEEP = 5  # Seconds to sleep between retries


def long2net(arg):
    if (arg <= 0 or arg >= 0xFFFFFFFF):
        raise ValueError("illegal netmask value", hex(arg))
    return 32 - int(round(math.log(0xFFFFFFFF - arg, 2)))


def to_CIDR_notation(bytes_network, bytes_netmask):
    network = scapy.utils.ltoa(bytes_network)
    netmask = long2net(bytes_netmask)
    net = "%s/%s" % (network, netmask)
    if netmask < 16:
        logger.warn("%s is too big. skipping" % net)
        return None

    return net


def scan_and_find_device(net, interface, timeout=1):
    logger.info("arping %s on %s" % (net, interface))
    try:
        ans, unans = scapy.layers.l2.arping(net, iface=interface, timeout=timeout, verbose=True)
        for s, r in ans.res:
            if r.src in MAC_ADDRESSES:
                line = r.sprintf("%Ether.src%  %ARP.psrc%")
                try:
                    hostname = socket.gethostbyaddr(r.psrc)
                    line += " " + hostname[0]
                except socket.herror:
                    # failed to resolve
                    pass
                logger.info('Phone found on the network')
                logger.info(line)
                return True
        return False
    except socket.error as e:
        if e.errno == errno.EPERM:     # Operation not permitted
            logger.error("%s. Did you run as root?", e.strerror)
        else:
            raise

if __name__ == "__main__":
    for i in range(RETRIES):
        logger.debug('Going to scan network - attempt {}'.format(i+1))
        for network, netmask, _, interface, address in scapy.config.conf.route.routes:

            # skip loopback network and default gw
            if network == 0 or interface == 'lo' or address == '127.0.0.1' or address == '0.0.0.0':
                continue

            if netmask <= 0 or netmask == 0xFFFFFFFF:
                continue

            net = to_CIDR_notation(network, netmask)

            # Skip network which I am not sure what it is
            if net == '169.254.0.0/16':
                continue

            if interface != scapy.config.conf.iface:
                # see http://trac.secdev.org/scapy/ticket/537
                logger.warn("skipping %s because scapy currently doesn't support arping on non-primary network interfaces", net)
                continue

            if net:
                print('going to scan {}, {}'.format(net, interface))
                found = scan_and_find_device(net, interface)
        if found:
            break
        sleep(SLEEP)

    process = subprocess.Popen('pgrep iCamSource', shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    pid, err = process.communicate()
    if found:
        # Close Icam if open
        if pid:
            logger.debug('Closing iCamSource')
            os.killpg(int(pid.strip()), signal.SIGTERM)
    else:
        # Open Icam if not already open
        if not pid:
            logger.debug('Opening iCamSource')
            os.system('/usr/bin/open -W -n -a /Applications/iCamSource.app/Contents/MacOS/iCamSource')
        else:
            logger.debug('iCamSource is already running with pid {}'.format(pid))
