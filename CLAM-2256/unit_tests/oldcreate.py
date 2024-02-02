#!/usr/bin/python3

PAYLOAD_FILE = 'test.c'



"""
TODO: Figure out how to add other code pages
self._start_of_compressed_data = 46
self._head._file_name_length = 11
self._head._file_attribute = 20
self._head._file_time_date = 3aba9ce1
self._head._file_descriptor = 10
self._head._unknown = 0
self._compression_method = 2
self._unknown = 0
self._file_crc = f7585f17
self._compressed_size = 52
self._uncompressed_size = 5d
self._file_name = alz test file.txt
self._enc_chk = 0 0 0 0 0 0 0 0 0 0 0 0
is_encrypted = false
is_data_descriptor = false
"""

f = open("test.alz", "wb")

#write alz file header
f.write(b'\x41\x4c\x5a\x01')

#write 'ignored' bytes
f.write(b'\x0a\x00\x00\x00')

#write local file header
f.write(b'\x42\x4c\x5a\x01')

#write the length of the filename
tempBytes = [len(PAYLOAD_FILE)]
f.write(bytes(tempBytes))
f.write(b'\x00')

#file attribute
f.write(b'\x20')

#time date
f.write(b'\xe1\x9c\xba\x3a')

#file descriptor
f.write(b'\x10')

#unknown
f.write(b'\x00')

#compression method (1 for bz2)
f.write(b'\x01')

#unknown
f.write(b'\x00')

#crc (6a307a2d for test.c)
f.write(b'\x2d\x7a\x30\x6a')

#compressed size (ls -l test.c.bz2 - 4 (sizeof bz2 file header)
#f.write(b'\x6f')
f.write(b'\x73')

#uncompressed size
f.write(b'\x4e')

f.write(b"test.c")

f2 = open("test.c.bz2", "rb")
data = f2.read()
f2.close()
#f.write(data[4:])
f.write(data)

#end of file shit
f.write(b'\x43\x4c\x5a\x01\x00\x00\x00\x00\x00\x00\x00\x00\x43\x4c\x5a\x02')






f.close()




