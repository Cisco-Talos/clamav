#!/usr/bin/python3

import sys, os
import shutil
import struct
from optparse import OptionParser

WORKING_DIRECTORY = ".__create_tmp"

def delWD():
    if os.path.isdir(WORKING_DIRECTORY):
        shutil.rmtree(WORKING_DIRECTORY)

def createWD():
    delWD()
    os.makedirs(WORKING_DIRECTORY)

def createInFiles():
    cwd = os.getcwd()
    os.chdir(WORKING_DIRECTORY)
    f = open("test.txt", "w")
    f.write("test file 0")
    f.close()

    for i in range(1, 5):
        os.makedirs(str(i))
        f = open(os.path.join(str(i), "test.txt"), "w")
        f.write(f'"test file {i}"')
        f.close()
    os.chdir(cwd)

def writeFileHeader(f):
    #write alz file header
    f.write(struct.pack('<i', 0x015a4c41))

    #write 'ignored' bytes
    f.write(struct.pack('<i', 0x0a))

def addFile(fileName, outFile):
    here;



parser = OptionParser()
parser.add_option("-o", "--out-file", help="Output file name", dest="outFile")
parser.add_option("-b", "--bzip2", action="store_true", help="Cannot be combined with uncompressed", dest="bz2")
parser.add_option("-u", "--uncompressed", action="store_true", help="Cannot be combined with bz2", dest="uncompressed")

(options, args) = parser.parse_args()

if ((options.bz2 and options.uncompressed)
        or None == options.outFile
        or (not options.bz2 and not options.uncompressed)):
    parser.print_help()
    sys.exit(1)

createWD()
createInFiles()

outFile = open(options.outFile, "wb")
writeFileHeader(outFile)

for parent, dirs, files in os.walk(WORKING_DIRECTORY):
    for f in files:
        fname = os.path.join(parent, f)
        addFile(fname, outFile)






