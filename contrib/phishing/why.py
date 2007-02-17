#!/usr/bin/env python
from popen2 import popen4;
import sys;
import os;
out = popen4("clamscan/clamscan -d database --phishing-strict-url-check --debug "+sys.argv[1])[0]
lines = out.read().split("\n")
PHISH_FOUND="Phishing found"
URL_CHECK="Checking url"
j=-1
for i in range(0,len(lines)):
	if lines[i].find(PHISH_FOUND)!=-1:
		j=i
		break

if j!=-1:
	print lines[j]
	i=j
	while lines[i].find(URL_CHECK)==-1:
		i = i-1
	for k in range(i,j):
		print lines[k]
#	os.system("TEMPFILE=`tempfile -s .eml` ; echo $TEMPFILE; cp "+sys.argv[1]+" $TEMPFILE; thunderbird $TEMPFILE")
else:
	print "Clean"
