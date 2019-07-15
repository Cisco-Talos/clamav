#!/bin/sh
# rebuilds the entire project

./cleanup.sh && ./autogen.sh && ./configure && make check all

# and to build the API docs: make -C doc 
# and before any release: make distcheck
