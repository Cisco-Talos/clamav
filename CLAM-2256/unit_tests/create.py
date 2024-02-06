#!/usr/bin/python3

import sys, os, bz2
import shutil
import binascii
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
    f.write(struct.pack('<I', 0x015a4c41))

    #write 'ignored' bytes
    f.write(struct.pack('<I', 0x0a))

def addFile(fileName, outFile, bzip2, inDir):

    #read in contents of the file
    data = open(fileName, "rb").read()

    #update the fileName so we don't have our working directory path in every file.
    fileName = fileName[1 + len(inDir):]

    #local file header
    outFile.write(struct.pack('<I', 0x015a4c42))

    #length of file name
    outFile.write(struct.pack('<H', len(fileName)))

    #file attribute
    outFile.write(b'\x20')

    #time date
    outFile.write(struct.pack('<I', 0))

    crc = binascii.crc32(data)
    uncompressedSize = len(data)
    if bzip2:
        #bzip2 the file
        data = bz2.compress(data)

    compressedSize = len(data)

    #file descriptor
    numBytes = 1
    if len(data) > 0xff:
        numBytes = 2
    if len(data) > 0xffff:
        numBytes = 4
    if len(data) > 0xffffffff:
        numBytes = 8
    
    outFile.write(struct.pack("<B", numBytes * 0x10))

    #unknown
    outFile.write(b'\x00')

    if bzip2:
        outFile.write(b'\x01')
    else:
        outFile.write(b'\x00')

    #unknown
    outFile.write(b'\x00')

    #write the crc
    outFile.write(struct.pack('<I', crc))

    if 1 == numBytes:
        outFile.write(struct.pack('<B', compressedSize))
        outFile.write(struct.pack('<B', uncompressedSize))
    elif 2 == numBytes:
        outFile.write(struct.pack('<H', compressedSize))
        outFile.write(struct.pack('<H', uncompressedSize))
    elif 4 == numBytes:
        outFile.write(struct.pack('<I', compressedSize))
        outFile.write(struct.pack('<I', uncompressedSize))
    elif 8 == numBytes:
        outFile.write(struct.pack('<Q', compressedSize))
        outFile.write(struct.pack('<Q', uncompressedSize))
    else:
        print ("Unsupported numBytes")
        import pdb ; pdb.set_trace()

    outFile.write(fileName.encode('utf-8'))

    outFile.write(data)



parser = OptionParser()
parser.add_option("-o", "--out-file", help="Output file name", dest="outFile")
parser.add_option("-b", "--bzip2", action="store_true", help="Cannot be combined with uncompressed", dest="bz2")
parser.add_option("-u", "--uncompressed", action="store_true", help="Cannot be combined with bz2", dest="uncompressed")
parser.add_option("-i", "--input", help="Cannot be combined with bz2", dest="input")

(options, args) = parser.parse_args()

if ((options.bz2 and options.uncompressed)
        or None == options.outFile
        or (not options.bz2 and not options.uncompressed)):
    parser.print_help()
    sys.exit(1)

if None == options.input:
    createWD()
    createInFiles()
    inDir = WORKING_DIRECTORY
else:
    inDir = options.input

if '/' == inDir or '\\' == inDir:
    parser.print_help()
    sys.exit(1)

while 1 < len(inDir):

    if '/' == inDir[len(inDir)-1] or '\\' == inDir[len(inDir)-1]:
        inDir = inDir[:-1]
    else:
        break

outFile = open(options.outFile, "wb")
writeFileHeader(outFile)

for parent, dirs, files in os.walk(inDir):
    for f in files:
        fname = os.path.join(parent, f)
        addFile(fname, outFile, options.bz2, inDir)

#end of file
outFile.write(b'\x43\x4c\x5a\x01\x00\x00\x00\x00\x00\x00\x00\x00\x43\x4c\x5a\x02')





