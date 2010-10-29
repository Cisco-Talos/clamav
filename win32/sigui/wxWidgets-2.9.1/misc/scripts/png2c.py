#!/usr/bin/python

# This script is a slightly modified version of the original found at
#
#       http://wiki.wxwidgets.org/Embedding_PNG_Images-Bin2c_In_Python
#
# without any copyright attribution so it is assumed it can be used under
# wxWindows licence as the rest of the wiki material.

import sys
import os
import os.path
import re
import array

USAGE = """png2c - Embed a PNG in a C header file (like XPM)
Usage: png2c [file ..] Output input PNG files as C structures on stdout"""

if len(sys.argv) < 2:
        print USAGE
        sys.exit(1)

r = re.compile("^([a-zA-Z._][a-zA-Z._0-9]*)[.][pP][nN][gG]$")

for path in sys.argv[1:]:
        filename = os.path.basename(path)
        m = r.match(filename)
        # Allow only filenames that make sense
        # as C variable names
        if not(m):
                print "Skipped file (unsuitable filename): " + filename
                continue

        # Read PNG file as character array
        bytes = array.array('B', open(path, "rb").read())
        count = len(bytes)

        # Create the C header
        text = "/* %s - %d bytes */\n" \
               "static const unsigned char %s_png[] = {\n" % (filename, count, m.group(1))

        # Iterate the characters, we want
        # lines like:
        #   0x01, 0x02, .... (8 values per line maximum)
        i = 0
        count = len(bytes)
        for byte in bytes:
                # Every new line starts with two whitespaces
                if (i % 8) == 0:
                        text += "  "
                # Then the hex data (up to 8 values per line)
                text += "0x%02x" % (byte)
                # Separate all but the last values
                if (i + 1) < count:
                        text += ", "
                if (i % 8) == 7:
                        text += '\n'
                i += 1

        # Now conclude the C source
        text += "};\n\n"

        print text
