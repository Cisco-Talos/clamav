#!/usr/bin/env python
def strlen(a,b):
	if len(a)<len(b):
		return -1;
	elif len(a)>len(b):
		return 1;
	else:
		return 0;

def getcommon_prefix(a,b):
	if a==b:
		return b;
	if a[:-1]==b[:-1]:
		return a[:-1];
	else:
		return ""

fil = file("iana_tld.h")
left = fil.read().split("(")
out=[]
for i in range(1,len(left)):
	right = left[i].split(")")
	regex_split = right[0].split("|")
	regex_split.sort()
	regex_split.sort(strlen)
	prefix=''
	prefixlen=0;
	c_map=''
	list=[]
	for val in regex_split:
		if val[:prefixlen] == prefix:
			if len(val) == (prefixlen+1):
				c_map = c_map+val[prefixlen]
			else:
	
				if len(c_map)>1:
					c_map = "["+c_map+"]"
				if len(prefix+c_map)>0:
					list.append(prefix+c_map)
				prefix = val[:-1]
				prefixlen=len(prefix)
				c_map=val[prefixlen]
		else:
			if len(c_map)>1:
				c_map = "["+c_map+"]"
			list.append(prefix+c_map)
			prefix = getcommon_prefix(prefix,val) 
			if len(prefix)==0:
				prefix=val[:-1]
			prefixlen=len(prefix)
			c_map=val[prefixlen]
 	if i==1:
		left0=left[0]
	else:
		left0=""
	out.append(left0)
	out.append("(")
	out.append("|".join(list))
	out.append(")")
	out.append(right[1])
print "".join(out)
