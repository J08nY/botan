#!/usr/bin/env python2

"""
Used to generate lib/tls/tls_suite_info.cpp from IANA params

(C) 2011, 2012, 2013, 2014, 2015, 2016, 2017 Jack Lloyd

Botan is released under the Simplified BSD License (see license.txt)
"""

import sys
import re
import datetime
import hashlib
import optparse

def to_ciphersuite_info(code, name):

    if(name.endswith('CCM') or name.endswith('CCM_8')):
       name += '_SHA256'

    (sig_and_kex,cipher_and_mac) = name.replace('CCM_8', 'CCM8').split('_WITH_')

    if sig_and_kex == 'RSA':
        sig_algo = 'IMPLICIT'
        kex_algo = 'RSA'
    elif 'PSK' in sig_and_kex:
        sig_algo = 'IMPLICIT'
        kex_algo = sig_and_kex
    elif 'SRP' in sig_and_kex:
        srp_info = sig_and_kex.split('_')
        if len(srp_info) == 2: # 'SRP_' + hash
            kex_algo = sig_and_kex
            sig_algo = 'IMPLICIT'
        else:
            kex_algo = '_'.join(srp_info[0:-1])
            sig_algo = srp_info[-1]
    else:
        (kex_algo, sig_algo) = sig_and_kex.split('_')

    sig_algo_fixups = {
        'anon': 'ANONYMOUS',
        'DSS': 'DSA'
        }

    if sig_algo in sig_algo_fixups:
        sig_algo = sig_algo_fixups[sig_algo]

    kex_algo_fixups = {
        'DHE': 'DH',
        'ECDHE': 'ECDH',
        'PSK_DHE': 'DHE_PSK',
        'RSA': 'STATIC_RSA',
        }

    if kex_algo in kex_algo_fixups:
        kex_algo = kex_algo_fixups[kex_algo]

    cipher_and_mac = cipher_and_mac.split('_')
    cipher_algo = '_'.join(cipher_and_mac[:-1])
    prf_algo = cipher_and_mac[-1]
    mode = cipher_and_mac[-2]

    cipher_algo = cipher_algo.replace('3DES_EDE', 'DES_EDE')

    if prf_algo == 'SHA':
        prf_algo = 'SHA1'

    if cipher_algo == 'CHACHA20_POLY1305':
        return (name, sig_algo, kex_algo, "CHACHA20_POLY1305", prf_algo, 'AEAD_XOR_12')

    if mode not in ['CBC', 'GCM', 'CCM8', 'CCM', 'OCB']:
        print("Unknown mode '%s' for ciphersuite %s (0x%d)" % (mode, name, int(code, 16)))
        sys.exit(1)

    if mode == 'CBC':
        return (name, sig_algo, kex_algo, cipher_algo + '_HMAC_' + prf_algo, prf_algo, 'CBC_MODE')
    elif mode == 'OCB':
        return (name, sig_algo, kex_algo, cipher_algo, prf_algo, 'AEAD_XOR_12')
    else:
        return (name, sig_algo, kex_algo, cipher_algo, prf_algo, 'AEAD_IMPLICIT_4')

def open_input(args):
    iana_url = 'https://www.iana.org/assignments/tls-parameters/tls-parameters.txt'

    if len(args) == 1:
        try:
            return open('tls-parameters.txt')
        except:
            pass

        import urllib2
        return urllib2.urlopen(iana_url)
    else:
         return open(args[1])

"""
Handle command line options
"""
def process_command_line(args):

    parser = optparse.OptionParser()

    parser.add_option('--with-ocb', action='store_true', default=True,
                      help='enable OCB AEAD suites')
    parser.add_option('--without-ocb', action='store_false', dest='with_ocb',
                      help='disable OCB AEAD suites')

    parser.add_option('--with-aria-cbc', action='store_true', default=False,
                      help='enable ARIA CBC suites')
    parser.add_option('--without-aria-cbc', action='store_false', dest='with_aria_cbc',
                      help='disable ARIA CBC suites')

    parser.add_option('--with-cecpq1', action='store_true', default=True,
                      help='enable CECPQ1 suites')
    parser.add_option('--without-cecpq1', action='store_false', dest='with_cecpq1',
                      help='disable CECPQ1 suites')

    parser.add_option('--with-srp-aead', action='store_true', default=False,
                      help='add SRP AEAD suites')
    parser.add_option('--without-srp-aead', action='store_false', dest='with_srp_aead',
                      help='disable SRP AEAD suites')

    parser.add_option('--save-download', action='store_true', default=False,
                      help='save downloaded tls-parameters.txt to cwd')

    parser.add_option('--output', '-o',
                      help='file to write output to (default %default)',
                      default='src/lib/tls/tls_suite_info.cpp')

    return parser.parse_args(args)

def main(args = None):
    if args is None:
        args = sys.argv

    weak_crypto = ['EXPORT', 'MD5', 'RC2', 'IDEA', 'RC4', '_DES_', 'WITH_NULL']
    static_dh = ['ECDH_ECDSA', 'ECDH_RSA', 'DH_DSS', 'DH_RSA'] # not supported
    protocol_goop = ['SCSV', 'KRB5']
    maybe_someday = ['RSA_PSK']
    not_supported = weak_crypto + static_dh + protocol_goop + maybe_someday

    (options, args) = process_command_line(args)

    if not options.with_aria_cbc:
        not_supported += ['ARIA_128_CBC', 'ARIA_256_CBC']

    ciphersuite_re = re.compile(' +0x([0-9a-fA-F][0-9a-fA-F]),0x([0-9a-fA-F][0-9a-fA-F]) + TLS_([A-Za-z_0-9]+) ')

    suites = {}
    suite_codes = {}

    contents = ''

    for line in open_input(args):
        contents += line
        match = ciphersuite_re.match(line)
        if match:
            code = match.group(1) + match.group(2)
            name = match.group(3)

            should_use = True
            for ns in not_supported:
                if ns in name:
                    should_use = False

            if should_use:
                suites[code] = to_ciphersuite_info(code, name)

    sha1 = hashlib.sha1()
    sha1.update(contents)
    contents_hash = sha1.hexdigest()

    if options.save_download:
        out = open('tls-parameters.txt', 'w')
        out.write(contents)
        out.close()

    def define_custom_ciphersuite(name, code):
        suites[code] = to_ciphersuite_info(code, name)

    if options.with_cecpq1:
        # CECPQ1 key exchange
        define_custom_ciphersuite('CECPQ1_RSA_WITH_CHACHA20_POLY1305_SHA256', '16B7')
        define_custom_ciphersuite('CECPQ1_ECDSA_WITH_CHACHA20_POLY1305_SHA256', '16B8')
        define_custom_ciphersuite('CECPQ1_RSA_WITH_AES_256_GCM_SHA384', '16B9')
        define_custom_ciphersuite('CECPQ1_ECDSA_WITH_AES_256_GCM_SHA384', '16BA')

    if options.with_ocb:
        # OCB ciphersuites draft-zauner-tls-aes-ocb-04
        define_custom_ciphersuite('DHE_RSA_WITH_AES_128_OCB_SHA256', 'FFC0')
        define_custom_ciphersuite('DHE_RSA_WITH_AES_256_OCB_SHA256', 'FFC1')
        define_custom_ciphersuite('ECDHE_RSA_WITH_AES_128_OCB_SHA256', 'FFC2')
        define_custom_ciphersuite('ECDHE_RSA_WITH_AES_256_OCB_SHA256', 'FFC3')
        define_custom_ciphersuite('ECDHE_ECDSA_WITH_AES_128_OCB_SHA256', 'FFC4')
        define_custom_ciphersuite('ECDHE_ECDSA_WITH_AES_256_OCB_SHA256', 'FFC5')

        define_custom_ciphersuite('PSK_WITH_AES_128_OCB_SHA256', 'FFC6')
        define_custom_ciphersuite('PSK_WITH_AES_256_OCB_SHA256', 'FFC7')
        define_custom_ciphersuite('DHE_PSK_WITH_AES_128_OCB_SHA256', 'FFC8')
        define_custom_ciphersuite('DHE_PSK_WITH_AES_256_OCB_SHA256', 'FFC9')
        define_custom_ciphersuite('ECDHE_PSK_WITH_AES_128_OCB_SHA256', 'FFCA')
        define_custom_ciphersuite('ECDHE_PSK_WITH_AES_256_OCB_SHA256', 'FFCB')

    if options.with_cecpq1 and options.with_ocb:
        # CECPQ1 OCB ciphersuites - Botan extension
        define_custom_ciphersuite('CECPQ1_RSA_WITH_AES_256_OCB_SHA256', 'FFCC')
        define_custom_ciphersuite('CECPQ1_ECDSA_WITH_AES_256_OCB_SHA256', 'FFCD')
        #define_custom_ciphersuite('CECPQ1_PSK_WITH_AES_256_OCB_SHA256', 'FFCE')

    if options.with_srp_aead:
        # SRP using GCM or OCB - Botan extension
        define_custom_ciphersuite('SRP_SHA_WITH_AES_256_GCM_SHA384', 'FFA0')
        define_custom_ciphersuite('SRP_SHA_RSA_WITH_AES_256_GCM_SHA384', 'FFA1')
        define_custom_ciphersuite('SRP_SHA_DSS_WITH_AES_256_GCM_SHA384', 'FFA2')
        define_custom_ciphersuite('SRP_SHA_ECDSA_WITH_AES_256_GCM_SHA384', 'FFA3')

        if options.with_ocb:
            define_custom_ciphersuite('SRP_SHA_WITH_AES_256_OCB_SHA256', 'FFA4')
            define_custom_ciphersuite('SRP_SHA_RSA_WITH_AES_256_OCB_SHA256', 'FFA5')
            define_custom_ciphersuite('SRP_SHA_DSS_WITH_AES_256_OCB_SHA256', 'FFA6')
            define_custom_ciphersuite('SRP_SHA_ECDSA_WITH_AES_256_OCB_SHA256', 'FFA7')

    suite_info = ''

    def header():
        return """/*
* TLS cipher suite information
*
* This file was automatically generated from the IANA assignments
* (tls-parameters.txt hash %s)
* by %s on %s
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

""" % (contents_hash, sys.argv[0], datetime.date.today().strftime("%Y-%m-%d"))

    suite_info += header()

    suite_info += """#include <botan/tls_ciphersuite.h>

namespace Botan {

namespace TLS {

//static
const std::vector<Ciphersuite>& Ciphersuite::all_known_ciphersuites()
   {
   // Note that this list of ciphersuites is ordered by id!
   static const std::vector<Ciphersuite> g_ciphersuite_list = {
"""

    for code in sorted(suites.keys()):
        info = suites[code]

        if info is None:
            continue

        assert len(info) == 6
        suite_expr = 'Ciphersuite(0x%s, "%s", Auth_Method::%s, Kex_Algo::%s, Cipher_Algo::%s, KDF_Algo::%s, Nonce_Format::%s)' % (
            code, info[0], info[1], info[2], info[3], info[4], info[5])

        suite_info += "      " + suite_expr + ",\n"

    suite_info += """      };

   return g_ciphersuite_list;
   }

}

}
"""

    if options.output == '-':
        print suite_info,
    else:
        out = open(options.output, 'w')
        out.write(suite_info)
        out.close()

if __name__ == '__main__':
    sys.exit(main())
