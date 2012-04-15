#!/usr/bin/python

import sys

template = sys.argv[1]
open_files = dict()

for i in sys.stdin:
    name, content = i.split (":", 1)
    if name not in open_files:
        open_files[name] = open (template % name, "w")
    open_files[name].write (content)
