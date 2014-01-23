#!/usr/bin/python

import sys
import StringIO
import hashlib
from optparse import OptionParser
from xml.dom import minidom
from xml.dom.minidom import Node

first = True
out = StringIO.StringIO()

def gtn(elm):
    """ get tag name"""
    if elm.nodeType == Node.TEXT_NODE:
        return "aaaaaaaa"
    else:
        return elm.tagName.lower()

def print_tag(elm, options, base="", depth=0):
    global first, out

    if elm.nodeType == Node.ELEMENT_NODE:
        # Element is a node, print name and addributes
        tname = elm.tagName.lower()
        # if this tag should be exluded skip the whole subtree
        if len(options.exclude_tag) > 0:
            if tname in [t.lower() for t in options.exclude_tag]:
                return
        if not first:
            out.write("\n\r")
        
        # attributes are ordered by name 
        attrs = elm.attributes
        sattrs = "&".join( 
                sorted( 
				[ k.lower()+'="'+attrs[k].value.lower().strip()+'"' for k in attrs.keys() if attrs[k].value.lower().strip() != "" ]
			 )
		)
        r = base+"/"+tname
        if sattrs!="":
           r+="?"+sattrs
        out.write(r)
        base = base+"/"+tname
    elif elm.nodeType == Node.TEXT_NODE:
        # text: print it
        text =  (elm.nodeValue or "").lower().strip()
        if text != "":
            out.write(" = %s" % text)

    first = False
    
    # child nodes ordered by name
    childnodes = dict( [ (gtn(e), e)  for e in elm.childNodes] )

    for key in sorted(childnodes.iterkeys()):
        print_tag(childnodes[key], options=options, base=base, depth=depth)

def main():
    global out
    usage = "usage: %prog [options]\n %procs create a flat and sorted output of an XML file and calucate a checksum."
    parser = OptionParser(usage)
    parser.add_option("-f", "--file", dest="filename", default=sys.stdin,
            help="read from FILE (default read from stdin)", metavar="FILE")
    parser.add_option("-d", "--dump",
            action="store_true", dest="dump", default=False,
            help="dump the flatified file")
    parser.add_option("-e", "--exclude-tag", 
            action="append", dest="exclude_tag", default=[],
            help="exclude this tag only (default none)")
    parser.add_option("-a", "--algorithm", dest="algorithm", default="md5",
            help="algorithm to compute the checksum (available: md5, sha1) (default: md5)")

    (options, args) = parser.parse_args()
    if options.filename != sys.stdin:
        fname = options.filename
        try:
            options.filename = open(fname)
        except Exception, e:
            print "Error: cannot open %s: %s" % (fname, e)

    doc = minidom.parse(options.filename)
    root = doc.documentElement
    print_tag(root, options=options)

    if options.filename != sys.stdin:
        try:
            options.filename.close()
        except Exception, e:
            print "Error: cannot close %s: %s" % (fname, e)

    out.write("\n\r")
    if options.dump:
        print out.getvalue()
    
    if options.algorithm == "md5":
        print "md5sum: " + hashlib.md5(out.getvalue()).hexdigest()
    elif options.algorithm == "sha1":
        print "sha1sum: " + hashlib.sha1(out.getvalue()).hexdigest()
    else:
        print "The algorithm isn't supported"

if __name__ == '__main__':
    main()
