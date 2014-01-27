#!/usr/bin/python

"""
This script produces a GNU/Linux iptables u32 rule matching against SIP requests.

The match is against the first line of the SIP message

Usage example:

./iptables-SIPu32.py udp "REGISTER sip:100@pbx.domain.local"


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

if len(sys.argv) < 3:
    print "Usage: %s [-d] udp|tcp 'text'" % sys.argv[0]
    print
    print "Example: "
    print "%s udp 'INVITE sip:ciccio.pasticcio@example.com:5060'\t\t to match all UDP INVITE to sip:ciccio.pasticcio@example.com:5060" % sys.argv[0] 
    print "the -d switch enables the debugging (not suitable for embedding in iptables commands)"
    sys.exit(-1)
   
proto = sys.argv[1]
search = sys.argv[2]
debug = False

tcp_base = "0>>22&0x3C@12>>26&0x3C@"
tcp_offset = 0
udp_base = "0>>22&0x3C@"
udp_offset = 8

if sys.argv[1] == "-d":
    debug = True
    proto = sys.argv[2]
    search = sys.argv[3]

if proto == "udp":
    base = udp_base
    offset = udp_offset
elif proto == "tcp":
    base = tcp_base
    offset = tcp_offset
else:
    print "Error: proto must be udp or tcp"
    sys.exit (-1)

step = 0
group = 0
hexstring = []
maskstring = ['00','00','00','00']

for char in search:
    step += 1
    hexstring.append("%02x" % ord(char))
    if (step % 4) == 0:
        if debug:
            print "POSITION: %s%i VALUE: %s (%s)" % ( base, (offset + (group*4)), flatten(hexstring), "".join(map(hex2char, hexstring)))
        else:
            sys.stdout.write("%s%i=%s" % ( base, (offset + (group*4)), flatten(hexstring)))
        hexstring = []
        group += 1
        if not debug:
            if step != len(search):
                sys.stdout.write(" && ")
            else:
                sys.stdout.write("")
if len(hexstring):
    for k in range (0, len(hexstring)):
        maskstring[k] = "FF"
    for k in range(0, (4 - len(hexstring))):
        hexstring.append("00")

    if debug:
        print "BITMASK: 0x%s" % "".join(maskstring)
        print "POSITION: %s%&0x%s VALUE: %s (%s)" % ( base, (offset + (group*4)), "".join(maskstring), flatten(hexstring), "".join(map(hex2char, hexstring)))
    else:
        sys.stdout.write("%s%i&0x%s=%s" % (base, (offset + (group*4)), "".join(maskstring), flatten(hexstring)))
