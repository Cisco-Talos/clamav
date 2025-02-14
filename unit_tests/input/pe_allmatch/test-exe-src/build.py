#!/bin/env python3

# Copyright (C) 2022-2025 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
#
# Authors: Andrew Williams
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2 as
# published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
# MA 02110-1301, USA.

'''
Build a `test.exe` program with distinctive features that may be easily detected by clamscan.
This program is also signed with an authenticode certificate to test authenticode certificate trust features.
'''

import errno
import os
import argparse
import random

parser = argparse.ArgumentParser()
parser.add_argument("os", choices=['windows', 'linux', 'win32', 'win64'], nargs='?', default='windows')
parser.add_argument("--no-sign", action='store_true', default=False)
parser.add_argument("--no-strip", action='store_true', default=False)
parser.add_argument("--no-cleanup", action='store_true', default=False)
args = parser.parse_args()

do_cleanup = not args.no_cleanup

if args.os == 'windows' or args.os == 'win32':
    prefix = 'i686-w64-mingw32-'
    do_res = True
    do_sign = not args.no_sign
    do_strip = not args.no_strip
    # __USE_MINGW_ANSI_STDIO lets %xd be used correctly when doing printf
    cc_flags = '-D__USE_MINGW_ANSI_STDIO=1'
    ext = ".exe"

elif args.os == 'win64':
    prefix = 'x86_64-w64-mingw32-'
    do_res = True
    do_sign = not args.no_sign
    do_strip = not args.no_strip
    cc_flags = '-D__USE_MINGW_ANSI_STDIO=1'
    ext = ".exe"

else: # linux
    prefix = ''
    do_res = False
    do_sign = False
    do_strip = False
    cc_flags = ''
    ext = ''

windres = '%swindres' % (prefix)
gcc = '%sgcc' % (prefix)
ld = '%sld' % (prefix)
strip = '%sstrip' % (prefix)

indicators = [
  # Indicators for the outer binary
  ('22df_62ba_15c8_f482', '1a0d_301b_228d_56c8'),

  # Indicators for up to 24 inner binaries
  ('ffa8_3994_1788_e8b6', 'e4d7_7b43_3155_040a'),
  ('3a28_3628_9dd8_9c32', '3da0_c7bc_1948_39bd'),
  ('d251_d598_8e5c_6f9d', 'ee01_7f34_e9c9_1ec1'),
  ('6761_4a90_365b_b4c0', 'b8b0_d765_3df3_e550'),
  ('7939_5658_544a_f991', '768b_f5e5_f5e4_1a3b'),
  ('d765_7e8b_90b9_4a2f', '6cb8_1966_8bc3_9874'),
  ('cef1_e295_6e46_f429', '0ef3_77f1_e811_2753'),
  ('8f8a_f7f2_cdd1_9d0b', '99aa_e67d_afb6_3735'),
  ('d183_4b76_bde9_f5fb', 'f5e2_acf2_ff78_88f7'),
  ('3bce_e84b_be85_77bc', 'b155_ac2c_22f6_cb9e'),
  ('6efd_bf13_3679_9d30', '00de_ce35_6606_114c'),
  ('6ef7_8f1c_19f8_9746', '38d9_f9c7_45de_9931'),
  ('54b5_a0a4_b852_d3ba', 'cc78_0d79_8e9d_6f8a'),
  ('7468_e227_c130_b48d', '0c57_4d6a_e113_e03a'),
  ('8272_e8e2_a133_2971', 'e113_d12a_266c_3253'),
  ('b552_7c09_8b0f_01c7', '01c3_a69a_899f_0764'),
  ('04a3_b125_45ed_2a8b', '58f8_6bf7_b1bb_c7b6'),
  ('5749_2c8c_9df1_4c7e', 'c0a0_3f27_99c5_51f4'),
  ('89df_0268_6c60_29fb', 'db58_4b5e_f2df_9b65'),
  ('c2cd_3a28_5180_dc7a', '2c70_5359_0a46_06fa'),
  ('6764_76f5_0e92_faa6', 'd07a_b1af_e36f_8894'),
  ('4e45_18c0_40da_e74d', '6a1d_d382_068a_7e71'),
  ('01c4_23f0_0e32_fad1', 'a2f0_7a46_5cf1_2e0d'),
  ('1cec_e7c0_daac_517f', '448a_2336_facf_e5e7'),
]

if len(indicators)-1 > 32:
    raise Exception("More embedded binaries than extract.h can handle")

try:
    os.mkdir('build')
except OSError as exc:
    if exc.errno != errno.EEXIST:
        raise
    pass

def run_cmd(cmd):
    print(cmd)
    if os.system(cmd):
        raise Exception("Command Failed: %s" % cmd)

def gen_ca_cert():
    run_cmd('openssl genrsa -out build/ca.key 4096')

    # TODO Explore making this cert have attributes that look more like
    # a real CA cert (ex: restrict its uses)
    subj = "/C=US/ST=Maryland/L=Fulton/O=Cisco Talos/OU=ClamAV Test CA %016x/emailAddress=rfc2606@example.net" % (random.randint(1,0xFFFFFFFFFFFFFFFF))
    cmd = 'openssl req -new -x509 -days 73000 -key build/ca.key -out build/ca.crt -subj "%s"' % (subj)
    run_cmd(cmd)

# https://blog.didierstevens.com/2008/12/30/howto-make-your-own-cert-with-openssl/
def gen_cs_cert(name, ext):
    key_name = 'build/%s%s.key' % (name, ext)
    csr_name = 'build/%s%s.csr' % (name, ext)
    crt_name = 'build/%s%s.crt' % (name, ext)

    run_cmd('openssl genrsa -out %s 4096' % (key_name))

    # TODO Explore making this cert have attributes that look more like
    # a real CS cert (ex: restrict its uses)
    subj = "/C=US/ST=Maryland/L=Fulton/O=Cisco Talos/OU=ClamAV Test %016x/emailAddress=rfc2606@example.net" % (random.randint(1,0xFFFFFFFFFFFFFFFF))
    cmd = 'openssl req -new -key %s -out %s -subj "%s"' % (key_name, csr_name, subj)
    run_cmd(cmd)

    cmd = 'openssl x509 -req -days 73000 -in %s -CA build/ca.crt -CAkey build/ca.key -out %s -set_serial %012d -extfile ./cs.extfile.cfg' % (csr_name, crt_name, random.randint(100000000000,999999999999))
    run_cmd(cmd)

    return (key_name, crt_name)

# https://blog.didierstevens.com/2018/09/24/quickpost-signing-windows-executables-on-kali/
def sign_exe(name, ext, cert_info):
    key_name = cert_info[0]
    crt_name = cert_info[1]
    orig_path = "build/%s%s" % (name, ext)
    signed_path = "build/%s-signed%s" % (name, ext)
    cmd = 'osslsigncode sign -certs %s -key %s -ts http://sha256timestamp.ws.symantec.com/sha256/timestamp -in %s -out %s' % (crt_name, key_name, orig_path, signed_path)
    run_cmd(cmd)
    os.unlink(orig_path)
    os.rename(signed_path, orig_path)

def build_exe(name, ext, index, cc_flags, do_res, do_strip, sources=['./test.c']):

    if do_res:
        # TODO Generate a new icon and new version information per exe.  The
        # icon can be generated with:
        #
        # head -c 245760 /dev/urandom | convert -depth 8 -size 320x256 RGB:- test.png
        # convert -background transparent test.png -define icon:auto-resize=16,32,48,64,256 test.ico
        #
        # NOTE ^^^ 245760 is 320x256x3
        res_path = 'build/%s%s.res' % (name, ext)
        cmd = '%s ./test.rc -O coff -o %s' % (windres, res_path)
        run_cmd(cmd)
        sources.append(res_path)

    cmd = '%s -Os %s %s -DINDICATOR1=\\"%s\\" -DINDICATOR2=\\"%s\\" -DINDEX=%d -o build/%s%s' % (gcc, cc_flags, ' '.join([x for x in sources]), indicators[index][0], indicators[index][1], index, name, ext)
    run_cmd(cmd)

    if do_strip:
        cmd = '%s --strip-all build/%s%s' %(strip, name, ext)
        run_cmd(cmd)

def package_exe(name, ext):
    # The name of the export symbols depends on the path, so we have to be in
    # the same directory as the exe we are packaging for the symbol name the
    # code expects to be generated.
    os.chdir('build')
    cmd = '%s -r -b binary %s%s -o %s%s.o' %(ld, name, ext, name, ext)
    run_cmd(cmd)
    os.chdir('..')

# Generate a new CA cert for code-signing
if do_sign:
    gen_ca_cert()

outer_exe_sources = ['./test.c']
# Build the inner exes. They MUST be named 'exe#', where # is the index. They
# can't have a file extension or else it breaks linking.
for i in range(1, len(indicators)):
    name = 'exe%d' % (i)
    inner_exe_ext = ".exe"
    build_exe(name, inner_exe_ext, i, cc_flags, False, do_strip);
    if do_sign:
        cert_info = gen_cs_cert(name, inner_exe_ext)
        sign_exe(name, inner_exe_ext, cert_info)
    package_exe(name, inner_exe_ext)
    outer_exe_sources.append('build/%s%s.o' % (name, inner_exe_ext))

# Build the outer exe
name = 'test'
build_exe(name, ext, 0, cc_flags, do_res, do_strip, sources=outer_exe_sources)
if do_sign:
    cert_info = gen_cs_cert(name, ext)
    sign_exe(name, ext, cert_info)

# Delete unneeded artifacts
if do_cleanup:
    cleanups = ['build/*.o']
    if do_sign:
        cleanups += ['build/*.csr', 'build/*.key']

    if do_res:
        cleanups += ['build/test.exe.res']

    for cleanup in cleanups:
        cmd = 'rm %s' % (cleanup)
        try:
            run_cmd(cmd)
        except:
            pass
