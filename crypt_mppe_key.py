#!/usr/bin/env python
###############################################################################
# crypt_mppe_key.py: Encrypt or decrypt RADIUS' MS-MPPE-Keys
###############################################################################
# Version: 1.0.1
###############################################################################
#
# Copyright (c) 2016,2017 garigouster
# Contact: garigouster dot git at google dot com
#
# This program is free software: you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the Free
# Software Foundation, either version 3 of the License, or (at your option)
# any later version.
#
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
# FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
# more details.
#
# You should have received a copy of the GNU General Public License along with
# this program. If not, see <http://www.gnu.org/licenses/>.
#
###############################################################################

PROGRAM = 'crypt_mppe_key.py'
VERSION = '1.0.1'
AUTHOR  = 'garigouster';
LICENSE = 'GPLv3';

from binascii import hexlify,unhexlify
from getopt import getopt,GetoptError
from hashlib import md5

import sys

# https://tools.ietf.org/html/rfc2548

def mppe_encrypt(clear,secret,authenticator,salt,pad="\0"):
    if len(clear) > 255:
        raise NameError('Bad clear data length')
    if len(authenticator) % 16:
        raise NameError('Bad request authenticator')
    if len(salt) != 2 or not ord(salt[0]) & 0x80:
        raise NameError('Bad salt')

    L = len(clear)
    M = chr(L) + clear
    M = M + pad*((16-len(M)%16)%16)
    C = []
    h = secret + authenticator + salt

    for p in [int(hexlify(M[i:i+16]),16) for i in range(0,len(M),16)]:
        b = int(hexlify(md5(h).digest()),16)
        c = unhexlify('%032x' % (b ^ p))
        C.append(c)
        h = secret + c

    return salt + ''.join(C)

def mppe_decrypt(cipher,secret,authenticator,pad="\0"):
    salt,C = cipher[0:2],cipher[2:]

    if len(C) % 16 or len(C) > 256:
        raise NameError('Bad encrypted data length')
    if len(authenticator) % 16:
        raise NameError('Bad request authenticator')
    if len(salt) != 2 or not ord(salt[0]) & 0x80:
        raise NameError('Bad salt')

    M = []
    h = secret + authenticator + salt

    for c in [C[i:i+16] for i in range(0,len(C),16)]:
        b = int(hexlify(md5(h).digest()),16)
        m = unhexlify('%032x' % (b ^ int(hexlify(c),16)))
        M.append(m)
        h = secret + c

    M = ''.join(M)
    L,clear = ord(M[0]),M[1:]

    if L > len(clear) or len(clear)-L > 15 or clear[L:] != pad * (len(clear)-L):
        raise NameError('Bad clear data')

    return clear[0:L]

def usage():
    print 'Description:'
    print ' '*4 + 'Encrypt or decrypt a MS-MPPE-Send-Key or MS-MPPE-Recv-Key attribute (of RADIUS messages).'
    print
    print 'Usage:'
    print ' '*4 + PROGRAM + ' [-e] [-s|h|b] shared-key clear-key authenticator salt'
    print ' '*4 + PROGRAM + ' -d [-s|h|b] shared-key ms-mppe-key authenticator'
    print
    print 'Options:'
    print ' '*4 + '-e (default)'
    print ' '*2*4 + 'Encrypt a clear key for a MS-MPPE-Send-Key/MS-MPPE-Recv-Key attribute'
    print ' '*4 + '-d'
    print ' '*2*4 + 'Decrypt a MS-MPPE-Send-Key/MS-MPPE-Recv-Key attribute for a clear key'
    print
    print 'Parameters:'
    print ' '*4 + 'shared-key   : the shared secret used by the RADIUS server/clients'
    print ' '*4 + 'clear-key    : the clear key to encrypt'
    print ' '*4 + 'ms-mppe-key  : the MS-MPPE-Send-Key/MS-MPPE-Recv-Key attribute to decrypt'
    print ' '*4 + 'authenticator: the authenticator attribute of previous RADIUS (Request) message'
    print ' '*4 + 'salt         : the salt (2 bytes) used to encrypt the clear key'
    print
    print ' '*4 + 'shared-key has to be a simple (ASCII) text.'
    print ' '*4 + 'clear-key, ms-mppe-key, authenticator and salt have to be hex strings'
    print ' '*4 + '(the digit sequence can be splited with colon signs).'
    print
    print 'Output switchs:'
    print ' '*4 + '-s (default)'
    print ' '*2*4 + 'hex string with 2-digit sequence splited with colon signs'
    print ' '*4 + '-h'
    print ' '*2*4 + 'full hex string'
    print ' '*4 + '-b'
    print ' '*2*4 + 'binary data'

if __name__ == '__main__':
    FORMAT_HEX_SEQUENCE = 's'
    FORMAT_HEX_STRING = 'h'
    FORMAT_BINARY = 'b'

    crypt = True
    format = FORMAT_HEX_SEQUENCE

    try:
        opts,args = getopt(sys.argv[1:],'desbh')
    except GetoptError:
        usage()
        sys.exit(1)

    for o,a in opts:
        if o == '-e':
            crypt = True
        elif o == '-d':
            crypt = False
        elif o == '-s':
            format = FORMAT_HEX_SEQUENCE
        elif o == '-h':
            format = FORMAT_HEX_STRING
        elif o == '-b':
            format = FORMAT_BINARY
        else:
            usage();
            sys.exit(1)

    if crypt and len(args) != 4 or not crypt and len(args) != 3:
        usage();
        sys.exit(1)

    shared_key = args[0]

    try:
        if crypt:
            clear_key,authenticator,salt = map(lambda hex: unhexlify(''.join(hex.split(':'))),args[1:4])
            res = mppe_encrypt(clear_key,shared_key,authenticator,salt)
        else:
            ms_mppe_key,authenticator = map(lambda hex: unhexlify(''.join(hex.split(':'))),args[1:3])
            res = mppe_decrypt(ms_mppe_key,shared_key,authenticator)
    except NameError as e:
        print e
        sys.exit(1)

    if format == FORMAT_HEX_SEQUENCE:
        out = ':'.join(map(hexlify,list(res))) + "\n"
    elif format == FORMAT_HEX_STRING:
        out = hexlify(res) + "\n"
    elif format == FORMAT_BINARY:
        out = res

    sys.stdout.write(out)

    sys.exit(0)
