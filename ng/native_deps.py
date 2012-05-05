#!/usr/bin/python

import sys


depend_file = sys.argv[1]
dependencies = dict ()

for line in open (depend_file):
  (target, deps) = line.split (":")
  dependencies[target] = filter (lambda s : len (s) > 0, map (lambda s : s.strip(), deps.split (" ")))


def step (result, cur_step):
  global dependencies
  next_step = []
  to_add = []
  for f in cur_step:
    for new_file in dependencies[f]:
      if new_file not in result:
        to_add += [new_file]
        next_step += [new_file]
  result = to_add + result
  return result, next_step

def handle_native_file (native_file):
  result = [native_file.replace (".native",".cmx")]
  cur_step = [native_file.replace (".native",".cmx")]
  while len (cur_step) > 0:
    result, cur_step = step (result, cur_step)
  print "%s: %s" % (native_file, " ".join(result))

for i in sys.argv[2:]:
  handle_native_file (i)
