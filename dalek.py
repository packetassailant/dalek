#!/usr/bin/env python2.7
# Dalek was tested on Ubuntu 12.04 and OSX ML
# ----------- OSX ---------------
# Install MongoDB via http://www.mongodb.org/downloads
# OSX Deps: pip install -U -r environment.txt
# ----------- Linux -------------
# Install MongoDB via http://www.mongodb.org/downloads
# Linux: sudo apt-get install python-pip
# Linux Deps: pip install -U -r environment.txt

from xml.etree.ElementTree import ElementTree
from pymongo.connection import Connection
from sets import Set
from operator import itemgetter

import os.path
import sys
import xlwt
import getopt
import socket
import struct

# Setup MongoDB Connection/Collections
conn = Connection('127.0.0.1')
ndb = conn['nessus-database']
ncollection = ndb['nessus-collection']
pcollection = ndb['nessus-port-collection']
ocollection = ndb['nessus-os-collection']


def usage():
    print 'Info:    Dalek was created by Chris Patten'
    print 'Purpose: To be a better Nessus parser'
    print 'Contact: cpatten[a.t.]packetresearch.com and @packetassailant\n'
    print 'Usage:   ./dalek.py -i <Nessus xml input file> -o <XLS output file>'
    print 'Note:    -i or --infile and -d or --dir are mutually exclusive'
    print '-h or --help        Print this help menu'
    print '-i or --infile      Nessus XML file (Required)'
    print '-d or --dir         Directory w/ multiple Nessus files (Required)'
    print '-o or --outfile     XLS output file name (Required)'
    print '-e or --exclude     Exclude Hosts with Empty Services'


def parsenessus(infile):
    ports_list = []
    nessus_dict = {}
    et = ElementTree()
    et.parse(infile)
    for e in et.getroot().getchildren():
        if e.tag == "Report":
            for f in e.getchildren():
                # Get IP address
                if f.tag == "ReportHost":
                    host = f.get("name")
                    nessus_dict["host"] = dottedQuadToNum(host)
                    for g in f.getchildren():
                        #Get OS and FQDN
                        if g.tag == "HostProperties":
                            # Create initial Dictionary entries for optional values
                            nessus_dict["os"] = "Unknown"
                            nessus_dict["fqdn"] = ""
                            for h in g.getchildren():
                                if h.tag == 'tag':
                                    if h.attrib['name'] == 'operating-system':
                                        os_list = h.text.splitlines()
                                        os = os_list[-1]
                                        nessus_dict["os"] = os
                                    if h.attrib['name'] == 'host-fqdn':
                                        fqdn = h.text
                                        nessus_dict["fqdn"] = fqdn
                        if g.tag == "ReportItem":
                            # Get Port list
                            port = g.get("port")
                            if port != "0":
                                svcn = g.get("svc_name").strip("?")
                                svcp = int(g.get("port"))
                                svcl = g.get("protocol")
                                port_tuple = svcn, svcp, svcl
                                ports_list.append(port_tuple)
                    sortedports = sortports(ports_list)
                    nessus_dict["ports"] = listports(sortedports)
                    insertnesscollection(nessus_dict)
                # Flush port list and nessus dictionary
                ports_list[:] = []
                nessus_dict.clear()


def sortports(portlist):
    uportlist = sorted(Set(portlist), key=itemgetter(1))
    return uportlist


def listports(sortedports):
    sortedportlist = []
    if not sortedports:
        sortedportlist = []
    else:
        for (service, port, prot) in sortedports:
            portstr = service + " " + "(" + str(port) + "/" + prot + ")"
            sortedportlist.append(portstr)
    return sortedportlist


def sortallports():
    allports_list = []
    allports_dict = {}
    portcursor = ncollection.find({}, {"_id": 0})
    for result in portcursor:
        if result['ports']:
            allports_list.extend(result['ports'])
    uniq_port_list = list(set(allports_list))
    for port in uniq_port_list:
        allports_dict["port"] = port
        allports_dict["count"] = allports_list.count(port)
        insertportcollection(allports_dict)


def sortallos():
    os_all_list = []
    allos_dict = {}
    oscursor = ncollection.find({}, {"_id": 0})
    for result in oscursor:
        if result['os']:
            os_all_list.append(result['os'])
    uniq_os_list = list(set(os_all_list))
    for os in uniq_os_list:
        allos_dict["os"] = os
        allos_dict["count"] = os_all_list.count(os)
        insertoscollection(allos_dict)


def insertportcollection(allports_dict):
    pcollection.insert({
        'port': allports_dict["port"],
        'count': allports_dict["count"]
    })


def insertoscollection(allos_dict):
    ocollection.insert({
        'os': allos_dict['os'],
        'count': allos_dict['count']
    })


def insertnesscollection(nessus_dict):
    ncollection.insert({
        'host': nessus_dict["host"],
        'os': nessus_dict["os"],
        'fqdn': nessus_dict["fqdn"],
        'ports': nessus_dict["ports"]
    })

def dottedQuadToNum(dotip):
    return struct.unpack('>L',socket.inet_aton(dotip))[0]

def numToDottedQuad(longip):
    return socket.inet_ntoa(struct.pack('>L',longip))

def natsortdb():
    return ncollection.find({}, {"_id": 0}).sort("host", 1)

def createwbk(sorted_list, found_e, outfile):
    ncount = 1
    pcount = 1
    ocount = 1
    wbook = xlwt.Workbook()
    nsheet = wbook.add_sheet('nessus_cumulative')
    osheet = wbook.add_sheet('nessus_os')
    psheet = wbook.add_sheet('nessus_ports')
    # Set Column Width
    nsheet.col(0).width = 5000
    nsheet.col(1).width = 7000
    nsheet.col(2).width = 9500
    nsheet.col(3).width = 7500
    psheet.col(0).width = 9000
    psheet.col(1).width = 5000
    osheet.col(0).width = 9000
    osheet.col(1).width = 5000
    # Title Row Style
    title_style = xlwt.easyxf(
        'font: height 200, name Arial Black;'
        'alignment: vertical center;'
    )
    # Normal Row Style
    row_style = xlwt.easyxf(
        'font: height 200, name Arial Black;'
        'alignment: vertical top, wrap on;'
    )
    # Create Nessus Cumulative Sheet
    nsheet.write(0, 0, 'Host/IP', title_style)
    nsheet.write(0, 1, 'Hostname', title_style)
    nsheet.write(0, 2, 'Operating System', title_style)
    nsheet.write(0, 3, 'Services', title_style)
    for result in sorted_list:
        if found_e is True:
            if result['ports'] and not None in result:
                nsheet.write(ncount, 0, numToDottedQuad(result['host']), row_style)
                nsheet.write(ncount, 1, result['fqdn'], row_style)
                nsheet.write(ncount, 2, result['os'], row_style)
                nsheet.write(ncount, 3, str("\n".join(result['ports'])), row_style)
                ncount += 1
        else:
            nsheet.write(ncount, 0, numToDottedQuad(result['host']), row_style)
            nsheet.write(ncount, 1, result['fqdn'], row_style)
            nsheet.write(ncount, 2, result['os'], row_style)
            nsheet.write(ncount, 3, str("\n".join(result['ports'])), row_style)
            ncount += 1
    # Create Port Sheet
    psheet.write(0, 0, 'Service', title_style)
    psheet.write(0, 1, 'Count', title_style)
    portcursor = pcollection.find({}, {"_id": 0}).sort('count', -1)
    for result in portcursor:
        psheet.write(pcount, 0, result['port'], row_style)
        psheet.write(pcount, 1, result['count'], row_style)
        pcount += 1
    # Create OS Sheet
    osheet.write(0, 0, 'Operating System', title_style)
    osheet.write(0, 1, 'Count', title_style)
    oscursor = ocollection.find({}, {"_id": 0}).sort('count', -1)
    for result in oscursor:
        osheet.write(ocount, 0, result['os'], row_style)
        osheet.write(ocount, 1, result['count'], row_style)
        ocount += 1
    wbook.save(outfile)


def readfilesindir(dirpath):
    path = dirpath
    nessus_files = [f for f in os.listdir(path) if f.endswith('.nessus')]
    return nessus_files


def removecollection():
    ncollection.drop()
    pcollection.drop()
    ocollection.drop()


def main():
    found_i = False
    found_o = False
    found_e = False
    found_d = False
    try:
        opts, args = getopt.getopt(sys.argv[1:], "hei:o:d:", ["infile=", "outfile=", "dir="])
    except getopt.GetoptError:
        usage()
        sys.exit(2)
    if len(opts) == 0:
        usage()
        sys.exit(2)
    for opt, arg in opts:
        if opt in ("-h", "--help"):
            usage()
            sys.exit(2)
        if found_i and found_d:
            print "Error: mutually exclusive -- use either -i --infile or -d --dir\n"
            usage()
            sys.exit(2)
        elif opt in ("-i", "--infile"):
            global infile
            infile = open(arg, 'r')
            found_i = True
        elif opt in ("-d", "--dir"):
            global nfiles
            ndir = arg
            found_d = True
        elif opt in ("-o", "--outfile"):
            global outfile
            outfile = open(arg, 'w')
            found_o = True
        elif not found_o:
            print "-o or --outfile is a mandatory argument"
            usage()
            sys.exit(2)
        elif opt in ("-e", "--exclude"):
            found_e = True
        else:
            assert False, "unhandled option"
    if found_d and not None:
        for nfile in readfilesindir(ndir):
            parsenessus(ndir + nfile)
    elif found_i and not None:
        parsenessus(infile)
    # Bootstrap - Sort Results/Create XLS/Drop Collection
    sorted_list = natsortdb()
    sortallports()
    sortallos()
    createwbk(sorted_list, found_e, outfile)
    removecollection()

if __name__ == '__main__':
    main()

'''
TODO List:
1. Add filtering for hosts without listening services (Done 12/14/2012 CP)
2. Add worksheet for total operating systems (Done 01/03/2013 CP)
3. Add worksheet for total services (Done 01/02/2013 CP)
4. Add support for multiple nessus files (Done 12/29/2012 CP)
5. Remove dependency for netaddr mod (Done 02/14/2013 CP)
'''
