#!/usr/bin/env python

# Remote Desktop Protocol (.rdp) file signing
# Copyright (C) 2024 Claudio Luck
# Copyright (C) 2015 Norbert Federa
# https://github.com/nfedera/rdpsign
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


import sys
import os
import argparse
import codecs
import subprocess
import tempfile

from struct import pack, unpack
from base64 import b64encode, b64decode


def error_exit(emsg):
    print("RDP FAIL - " + emsg)
    sys.exit(3)


def main(argv):
    securesettings = {}
    signscope_settings = {}
    for attrname, attrtype, signscopename in [
        [ 'full address', 's', 'Full Address' ],
        [ 'alternate full address', 's', 'Alternate Full Address' ],
        [ 'pcb', 's', 'PCB' ],
        [ 'use redirection server name', 'i', 'Use Redirection Server Name' ],
        [ 'server port', 'i', 'Server Port' ],
        [ 'negotiate security layer', 'i', 'Negotiate Security Layer' ],
        [ 'enablecredsspsupport', 'i', 'EnableCredSspSupport' ],
        [ 'disableconnectionsharing', 'i', 'DisableConnectionSharing' ],
        [ 'autoreconnection enabled', 'i', 'AutoReconnection Enabled' ],
        [ 'gatewayhostname', 's', 'GatewayHostname' ],
        [ 'gatewayusagemethod', 'i', 'GatewayUsageMethod' ],
        [ 'gatewayprofileusagemethod', 'i', 'GatewayProfileUsageMethod' ],
        [ 'gatewaycredentialssource', 'i', 'GatewayCredentialsSource' ],
        [ 'support url', 's', 'Support URL' ],
        [ 'promptcredentialonce', 'i', 'PromptCredentialOnce' ],
        [ 'require pre-authentication', 'i', 'Require pre-authentication' ],
        [ 'pre-authentication server address', 's', 'Pre-authentication server address' ],
        [ 'alternate shell', 's', 'Alternate Shell' ],
        [ 'shell working directory', 's', 'Shell Working Directory' ],
        [ 'remoteapplicationprogram', 's', 'RemoteApplicationProgram' ],
        [ 'remoteapplicationexpandworkingdir', 's', 'RemoteApplicationExpandWorkingdir' ],
        [ 'remoteapplicationmode', 'i', 'RemoteApplicationMode' ],
        [ 'remoteapplicationguid', 's', 'RemoteApplicationGuid' ],
        [ 'remoteapplicationname', 's', 'RemoteApplicationName' ],
        [ 'remoteapplicationicon', 's', 'RemoteApplicationIcon' ],
        [ 'remoteapplicationfile', 's', 'RemoteApplicationFile' ],
        [ 'remoteapplicationfileextensions', 's', 'RemoteApplicationFileExtensions' ],
        [ 'remoteapplicationcmdline', 's', 'RemoteApplicationCmdLine' ],
        [ 'remoteapplicationexpandcmdline', 's', 'RemoteApplicationExpandCmdLine' ],
        [ 'prompt for credentials', 'i', 'Prompt For Credentials' ],
        [ 'authentication level', 'i', 'Authentication Level' ],
        [ 'audiomode', 'i', 'AudioMode' ],
        [ 'redirectdrives', 'i', 'RedirectDrives' ],
        [ 'redirectprinters', 'i', 'RedirectPrinters' ],
        [ 'redirectcomports', 'i', 'RedirectCOMPorts' ],
        [ 'redirectsmartcards', 'i', 'RedirectSmartCards' ],
        [ 'redirectposdevices', 'i', 'RedirectPOSDevices' ],
        [ 'redirectclipboard', 'i', 'RedirectClipboard' ],
        [ 'devicestoredirect', 's', 'DevicesToRedirect' ],
        [ 'drivestoredirect', 's', 'DrivesToRedirect' ],
        [ 'loadbalanceinfo', 's', 'LoadBalanceInfo' ],
        [ 'redirectdirectx', 'i', 'RedirectDirectX' ],
        [ 'rdgiskdcproxy', 'i', 'RDGIsKDCProxy' ],
        [ 'kdcproxyname', 's', 'KDCProxyName' ],
        [ 'eventloguploadaddress', 's', 'EventLogUploadAddress' ],
    ]:
        securesettings[attrname] = signscope_settings[signscopename] = (attrname, attrtype, signscopename)

    parser = argparse.ArgumentParser('rdpsign')
    parser.add_argument("infile", metavar='infile.rdp', help="rdp file to be verified")
    parser.add_argument("--CAfile", metavar='CAfile', default="/etc/ssl/certs/ca-certificates.crt",
                        help="CAfile (default is /etc/ssl/certs/ca-certificates.crt)")
    parser.add_argument("--check-fp", metavar='fingerprint', default=None,
                        help="Also check SHA256 Fingerprint of signing certificate (if signature is valid)")
    parser.add_argument("--check-dns", metavar='dns', action='append', default=[],
                        help="Also check for DNS name present (if signature is valid)")
    parser.add_argument("--showcert", action='store_true', default=False,
                        help="Show signing certificate (if signature is valid)")
    parser.add_argument("-e", dest='encoding', metavar='encoding', default="unicode",
                        help="encoding of input file (default is to detect unicode types)")

    args = parser.parse_args(argv[1:])

    env = dict(os.environ)
    env['LC_ALL'] = 'C'
    env['LANG'] = 'C'

    settings = list()
    signlines = list()
    signnames = list()
    signscope = set()
    msgsig = b'\x01\x00\x01\x00\x01\x00\x00\x00\x00\x00\x00\x00' # = pack('<III', 0x00010001, 0x00000001, 0x0)
    
    output_errors = []  # [ ({0=info,1=warn,2=critical,3=unknown}, message) ]

    try:
        with open(args.infile, 'rb') as f:
            rdpdata = f.read()
        encoding = args.encoding
        bomsize = 0
        if encoding == 'unicode':
            if rdpdata[0:3] == codecs.BOM_UTF8:
                encoding = 'utf-8-sig'
                bomsize = 3
            elif rdpdata[0:2] == codecs.BOM_UTF16_LE:
                encoding = 'utf-16-le'
                bomsize = 2
            elif rdpdata[0:2] == codecs.BOM_UTF16_BE:
                encoding = 'utf-16-be'
                bomsize = 2
            elif rdpdata[0:4] == codecs.BOM_UTF32_LE:
                encoding = 'utf-32-le'
                bomsize = 4
            elif rdpdata[0:4] == codecs.BOM_UTF32_BE:
                encoding = 'utf-32-be'
                bomsize = 4
            else:
                encoding = 'utf-8'
        rdptext = rdpdata[bomsize:].decode(encoding)
        lines = [ v.strip() for v in rdptext.split('\n') ]
    except Exception as e:
        error_exit('Error reading rdp file: '+ str(e))

    # fixme: check successful read, size of settings etc

    fulladdress = None
    alternatefulladdress = None
    certs = []
    output_cert_text = []
    output_trail = []
    check_fp_valid = None
    check_dns_valid = None
            
    def add_signscope(sigscopename):
        sigscopename = sigscopename.strip()
        secureargname, secureargtype, _ = signscope_settings.get(sigscopename, (None, None, None))
        if secureargname is not None:
            signscope.add((secureargname, secureargtype))

    for line in lines:
        if not line:
            continue
        try:
            argname, argtype, argval = line.split(':', 2)
        except:
            raise Exception(f"RDP file format error: '{line}'")
        if (argname, argtype) == ('full address', 's'):
            fulladdress = argval
        elif (argname, argtype) == ('alternate full address', 's'):
            alternatefulladdress = argval
        elif (argname, argtype) == ('signature', 's'):
            msgsig = b64decode(argval)
            continue
        elif (argname, argtype) == ('signscope', 's'):
            [ add_signscope(scope) for scope in argval.split(',') ]
            continue
        elif argtype not in ('s', 'i', 'b'):
            raise Exception(f"RDP file format error: '{line}'")
        settings.append((argname, argtype, argval, line))

    # prevent hacks via alternate full address

    if fulladdress and not alternatefulladdress:
        settings.append('alternate full address:s:' + fulladdress)

    for secargname, secargtype, secsigscopename in securesettings.values():
        if len(signscope) != 0 and (secargname, secargtype) not in signscope:
            continue
        for argname, argtype, argval, line in settings:
            if argname == secargname and argtype == secargtype:
                signnames.append(secsigscopename)
                signlines.append(line)

    msgtext = '\r\n'.join(signlines) + '\r\n' + 'signscope:s:' + ','.join(signnames) + '\r\n' + '\x00'

    msgblob = msgtext.encode('UTF-16LE')

    byte1, byte2, msgsiglen = unpack('<III', msgsig[0:12])
    if byte1 != 0x00010001 or byte2 != 0x00000001:
        error_exit('Bad signature in RDP file')
    elif len(msgsig) - 12 < msgsiglen:
        error_exit('Signature length mismatch in RDP file')
    elif len(msgsig) - 12 > msgsiglen:
        output_errors.append((1, 'Signature length mismatch in RDP file (trailing data)'))
        msgsig = msgsig[0:msgsiglen+13]

    opensslin = msgsig[12:]

    with tempfile.NamedTemporaryFile() as tmpsigfile:
        tmpsigfile.write(opensslin)
        tmpsigfile.flush()

        params  = [ 'openssl', 'smime', '-verify', '-binary' ]
        params += [ '-content', '/dev/stdin' ]
        params += [ '-inform', 'DER', '-in', tmpsigfile.name ]
        params += [ '-noattr', '-nosmimecap' ]
        params += [ '-CAfile', args.CAfile ]
        params += [ '-purpose', 'any' ]
        params += [ '-out', '/dev/null' ]
            
        try:
            proc = subprocess.Popen(
                params,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=env)

            opensslout, opensslerr = proc.communicate(msgblob)
        except OSError as e:
            error_exit('Error calling openssl command: ' + e.strerror)
    
        retcode = proc.poll()

        if retcode != 0:
            emsg = 'openssl command failed (return code #{0:d})'.format(retcode)
            if opensslerr is not None:
                emsg += ':\n'
                emsg += opensslerr.decode('utf-8')
            error_exit(emsg)

        output_errors.append((0, 'RDP signature is valid'))
        
        params  = [ 'openssl', 'pkcs7', '-inform', 'DER', '-in', tmpsigfile.name ]
        params += [ '-print_certs' ]

        try:
            proc = subprocess.Popen(
                params,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=env)

            opensslout, opensslerr = proc.communicate('')
        except OSError as e:
            error_exit('Error calling openssl command: ' + e.strerror)
        
        retcode = proc.poll()

        if retcode != 0:
            emsg = 'openssl command failed (return code #{0:d})'.format(retcode)
            if opensslerr is not None:
                emsg += ':\n'
                emsg += opensslerr.decode('utf-8')
            error_exit(emsg)

    current_cert = None
    for line in opensslout.split(b'\n'):
        if line == b'-----BEGIN CERTIFICATE-----':
            current_cert = len(certs)
            certs.append(line + b'\n')
        elif line == b'-----END CERTIFICATE-----':
            certs[current_cert] += line + b'\n'
            current_cert = None
        elif current_cert is not None:
            certs[current_cert] += line + b'\n'

    params  = [ 'openssl', 'x509', '-inform', 'PEM', '-in', '/dev/stdin', '-noout' ]
    params += [ '-text', '-subject', '-ext', 'subjectAltName' ]
    params += [ '-sha256', '-fingerprint' ]

    proc_term_encoding = 'utf-8'

    try:
        proc = subprocess.Popen(
            params,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env)

        opensslout, opensslerr = proc.communicate(certs[0])
    except OSError as e:
        error_exit('Error calling openssl command: ' + e.strerror)

    retcode = proc.poll()

    if retcode != 0:
        emsg = 'openssl command failed (return code #{0:d})'.format(retcode)
        if opensslerr is not None:
            emsg += ':\n'
            emsg += opensslerr.decode('utf-8')
        error_exit(emsg)

    sys.stderr.buffer.write(opensslerr)
    
    parse_in_cert = False
    parse_in_trail = False
    for line in opensslout.decode(proc_term_encoding).split('\n'):
        line = line + '\n'
        if line.startswith('Certificate:'):
            parse_in_cert = True
            output_cert_text.append(line)
        elif not line.startswith('    '):
            if parse_in_cert:
                parse_in_trail = True
            parse_in_cert = False
            output_trail.append(line)
        elif parse_in_trail:
            output_trail.append(line)
        elif parse_in_cert:
            output_cert_text.append(line)

    if args.check_fp:
        #output_errors.append((0, 'Checking fingerprint'))
        check_fp_valid = False
        shouldbe_fp = ''.join(args.check_fp.split(':')).lower()
        for line in output_trail:
            if line.startswith('sha256 Fingerprint='):
                _, _, fp = line.partition('=')
                have_fp = ''.join(fp.rstrip('\n').split(':')).lower()
                if have_fp == shouldbe_fp:
                    check_fp_valid = True
                else:
                    output_errors.append((2, 'Fingerprint does not match'))

    if len(args.check_dns):
        parse_in_san = False
        sans = []
        for line in output_trail:
            if line.startswith('subject=CN = '):
                parse_in_san = False
                sans.append('DNS:' + line[13:].rstrip('\n'))
            elif line.startswith('X509v3 Subject Alternative Name:'):
                parse_in_san = True
            elif parse_in_san:
                if line.startswith('    '):
                    sans.append(line.rstrip('\n'))
                else:
                    parse_in_san = False
        sans = [ s.strip() for s in ', '.join(sans).split(',') ]
        sans = set(( s[4:] for s in sans if s.startswith('DNS:') ))

        check_dns_valid = True
        #output_errors.append((0, 'Checking DNS names'))
        for shouldbe_san in args.check_dns:
            if shouldbe_san not in sans:
                output_errors.append((2, f'DNS name missing in SAN and/or CN ({shouldbe_san})'))
                check_dns_valid = False
    
    retval = 0
    max_errlevel = 0
    errtype = {0: 'INFO', 1: 'WARNING', 2: 'ERROR', 3: 'UNKNONW'}
    for errlevel, errmsg in output_errors:
        max_errlevel = max(max_errlevel, errlevel)
    if max_errlevel == 0:
        text_output = f"RDP OK - {args.infile}"
    else:
        text_output = f"RDP ERROR ({max_errlevel}) - {args.infile}"

    print(text_output)

    for errlevel, errmsg in output_errors:
        print('{0}: {1}'.format(errtype[errlevel], errmsg))

    if args.showcert:
        for line in output_cert_text:
            sys.stdout.write(line)

    return max_errlevel


if __name__ == "__main__":
    main(sys.argv)

