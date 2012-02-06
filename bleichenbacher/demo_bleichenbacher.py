#import random, struct, subprocess
#import os, sys, math, time
#import Crypto.Util.number
#import Crypto.PublicKey.RSA

import random, struct, os, sys


# Trivial functions

def compute_b(n):
  """Compute B as defined in the paper."""
  k = keylen (n)
  return 2 ** (8*(k-2))

def str_to_bigint (s):
  return long (s.encode("hex"), 16)

def bigint_to_str (i):
  s = "%x" % i
  if len (s) % 2 == 1:
    s = "0" + s
  return s.decode ("hex")

def keylen (n):
  return len (bigint_to_str (n))


# PKCS1 primitives

def pkcs1_padding(data, keylen):
  """Append a PKCS#1 padding to the data based of the key length."""
  if len(data) > keylen-11:
    print >> sys.stderr, "pkcs_padding: data length it too long !"
    sys.exit()

  padding = ""
  for i in range(keylen - len(data) - 3):
    padding += struct.pack("!B", random.randint(1,255))

  return "\x00\x02" + padding + "\x00" + data

def is_pkcs1_compliant(data):
  if data[:2] != "\x00\x02":
    return False
  else:
    for c in data[2:]:
      if c == "\00":
        return True
    return False


# Higher-level primitives

def oracle (n, d, c):
  m = pow (c, d, n)
  data = bigint_to_str (m)
  return is_pkcs1_compliant (data)

def mk_test (n, e, data):
  k = keylen (n)
  s = pkcs1_padding (data, k)
  m = str_to_bigint (s)
  c = pow (m, e, n)
  context = {}
  context["n"] = n
  context["e"] = e
  b = compute_b (n)
  context["b"] = b
  
  # Note: blinding is not needed when c is already PKCS compliant (i.e. it is an encrypted message)
  context["c"] = c
  context["s"] = [1]
  context["M"] = {}
  context["M"][0] = [(2*b, (3*b) -1)]

  return context


n = 0xbddcbf24b1b95ebcd631d3b5ef5c8b47
e = 3
d = 0x7e932a18767b947cbb8e9093cdcb5f4b

context = mk_test (n, e, "test")



# context = {}

# def smallest_compliant(data, max_value):
#   start = time.time()
#   candidate = max_value
#   while True:
#     tmp = (data * (candidate**e)) % n # XXX: super slow
#     ret = pkey._decrypt(tmp)
#     if is_pkcs1_compliant(Crypto.Util.number.long_to_bytes(ret, blocksize=KEYLEN)):
#       return tmp, candidate
#     candidate += 1

# tmp = (c * (1**e)) % n
# context["s"] = [1]
# context["c"] = [tmp]
# b = compute_b(KEYLEN)
# context["M"] = {}
# context["M"][0] = [(2*b, (3*b) -1)]

# i = 1
# while True:
#   # Step 2 - Searching for PKCS conforming messages
#   if i == 1:
#   # Step 2.a - Starting the search
#     start = time.time()
#     print "+ Entering step 2.a"
#     top = int(math.ceil(float(n) / (3*compute_b(KEYLEN))))
    
#     ret_c, ret_s = smallest_compliant(context["c"][0], top)
#     context["s"] += [ret_s]
#     context["c"] += [ret_c]

#     print "   s%i found: %i" % (i, ret_s)
#     print "- Exiting step 2.a - %.2fs" % (time.time()-start)

#   elif i > 1 and len(context["M"][i-1]) >= 2:
#   # Step 2.b - Searching with more than one interval left
#     start = time.time()
#     print "+ Entering step 2.b"
#     top = context["s"][i-1] + 1
#     ret_c, ret_s = smallest_compliant(context["c"][0], top)
#     context["s"] += [ret_s]
#     context["c"] += [ret_c]
#     print "   s%i found: %i" % (i, ret_s)
#     print "- Exiting step 2.b - %.2fs" % (time.time()-start)

#   elif len(context["M"][i-1]) == 1:
#   # Step 2.c - Searching with one interval left
#     start = time.time()
#     print "+ Entering step 2.c"
#     a,b = context["M"][i-1][0]
#     B = compute_b(KEYLEN)

#     tmp_1 = 2 * ((b * context["s"][i-1] - 2 * B) / n)
#     ri = int(math.ceil(tmp_1))

#     ret_s = None
#     while True:
#       tmp_2_l = int(math.floor((2*B + ri*n) / b))
#       tmp_2_r = int(math.ceil((3*B + ri*n) / a))
#       for i in range(tmp_2_l, tmp_2_r):
# 	tmp = (context["c"][0] * (i**e)) % n
#         ret = pkey._decrypt(tmp)
#         if is_pkcs1_compliant(Crypto.Util.number.long_to_bytes(ret, blocksize=KEYLEN)):
# 	  ret_s = i
# 	  break
      
#       ri += 1
#     print "   s%i found: %i" % (i, ret_s)
#     print "- Exiting step 2.c - %.2fs" % (time.time()-start)

#   else:
#     print "ERROR: it should not happen !"
#     print "       ", i
#     print "       ", context["s"]
#     print "       ", context["M"]
#     sys.exit()

#   # Step 3 - Narrowing the set of solutions
#   start = time.time()
#   print "+ Entering step 3"
#   ret_list = set()
#   tmp_B = compute_b(KEYLEN)
#   tmp_l = context["M"][i-1]
#   for tmp_M in tmp_l:
#     a = tmp_M[0]
#     b = tmp_M[1]
#     tmp_l = int(math.floor((a*context["s"][i] - 3*tmp_B +1) /float(n)))
#     tmp_r = int(math.ceil( (b*context["s"][i] - 2*tmp_B)    /float(n)))
#     for r in range(tmp_l, tmp_r+1):
#       tmp_a = int(max(a, math.floor((2*tmp_B + r*n) / float(context["s"][i]))))
#       tmp_b = int(min(b, math.ceil((3*tmp_B -1 + r*n)/ float(context["s"][i]))))
#       print "a", a, (2*tmp_B + r*n) / context["s"][i]
#       print "b", b, (3*tmp_B -1 + r*n)/ context["s"][i]
#       if tmp_a <= tmp_b:
#         ret_list.add((tmp_a, tmp_b))
#       #elif tmp_b <= tmp_a:
#       #  ret_list.add((tmp_b, tmp_a))
#       if len(ret_list):
# 	break

#   context["M"][i] = list(ret_list)
#   print "   %i sets computed" % len(context["M"][i])
#   print "   ", context["M"]
#   print "- Exiting step 3 - %.2fs" % (time.time()-start)

#   # Step 4 - Computing the solution
#   if len(context["M"][i]) == 1:
#     if context["M"][i][0][0] == context["M"][i][0][1]:
#       print "WE GOT THE SOLUTION ?!?"

#   i += 1
#   print "= = = ="
