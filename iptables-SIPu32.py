#!/usr/bin/python

"""
This script produces a GNU/Linux iptables u32 rule matching against SIP requests.

The match is against the first line of the SIP message

Usage:

./iptables-SIPu32.py REGISTER sip:100@pbx.domain.local

iptables -I OUTPUT 1 -p udp  \! -f -m u32 --u32 $(./iptables-SIPu32.py "INVITE sip:3381234567") -j LOG --log-prefix "INVITE to my cell"
"""


import sys

def hex2char(s):
    char = int(s,16)
    return chr(char)

def flatten(array):
    result = "0x"
    for char in array:
        result += char
    return result

if len(sys.argv) < 2:
    print "Usage: %s [-d] 'text'" % sys.argv[0]
    print
    print "Example: "
    print "%s 'INVITE sip:ciccio.pasticcio@example.com:5060'\t\t to match all INVITE to sip:ciccio.pasticcio@example.com:5060" % sys.argv[0] 
    print "\nThe -d switch enables the debugging (not suitable for embedding in iptables commands)"
    print "\n"
    print "This script works only with SIP over UDP."
    sys.exit(-1)
   
   
search = sys.argv[1]
debug = False

if sys.argv[1] == "-d":
    debug = True
    search = sys.argv[2]


step = 0
group = 0
hexstring = []
maskstring = ['00','00','00','00']

for char in search:
    step += 1
    hexstring.append("%02x" % ord(char))
    if (step % 4) == 0:
        if debug:
            print "POSITION: 0>>22&0x3C@%i VALUE: %s (%s)" % ( (8+(group*4)), flatten(hexstring), "".join(map(hex2char, hexstring)))
        else:
            sys.stdout.write("0>>22&0x3C@%i=%s" % ( (8+(group*4)), flatten(hexstring)))
        hexstring = []
        group += 1
        if not debug:
            if step != len(search):
                sys.stdout.write("&&")
            else:
                sys.stdout.write("")
if len(hexstring):
    for k in range (0, len(hexstring)):
        maskstring[k] = "FF"
    for k in range(0, (4 - len(hexstring))):
        hexstring.append("00")

    if debug:
        print "BITMASK: 0x%s" % "".join(maskstring)
        print "POSITION: 0>>22&0x3C@%i&0x%s VALUE: %s (%s)" % ( (8+(group*4)), "".join(maskstring), flatten(hexstring), "".join(map(hex2char, hexstring)))
    else:
        sys.stdout.write("0>>22&0x3C@%i&0x%s=%s" % ( (8+(group*4)), "".join(maskstring), flatten(hexstring)))
