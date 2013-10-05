Dalek
=====

Dalek - Nessus Report Parser

## Objective
Dalek is a Python/MongoDB application that parses Nessus Vulnerability Scanner xml (i.e., .nessus) files. The application leverages the xlwt libraries to create an excel workbook consisting of three spreadsheet tabs:

1. Cumulative Information in the form of:
	* Hostname/IP
	* FQDN
	* Operating System
	* Open Services (UDP/TCP)

2. Operating System(s) in the form of:
	* Operating System
	* Number of times each OS was detected

3. TCP/UDP services in the form of:
	* Service(s) detected
	* Number of times each service was detected

The one thing that has been excluded from this project is the parsing of vulnerability data since this was truly only intended to help create ancillary tables. This project is intended to help represent high level data often necessary during security assessments, such as a penetration test. 


## Usage
$ python dalek.py <br>
Info:    Dalek was created by Chris Patten  <br>
Purpose: To be a better Nessus parser  <br>
Contact: cpatten[a.t.]packetresearch.com and @packetassailant  <br> <br>

Usage:   ./dalek.py -i <Nessus xml input file> -o <XLS output file>  <br>
Note:    -i or --infile and -d or --dir are mutually exclusive  <br>
-h or --help        Print this help menu  <br>
-i or --infile      Nessus XML file (Required)  <br>
-d or --dir         Directory w/ multiple Nessus files (Required)  <br>
-o or --outfile     XLS output file name (Required)  <br>
-e or --exclude     Exclude Hosts with Empty Services  <br>

## Installation 
# Dalek was tested on Ubuntu 12.04 and OSX ML
# ----------- OSX ---------------
# Install MongoDB via http://www.mongodb.org/downloads
# OSX Deps: pip install -U -r environment.txt
# ----------- Linux -------------
# Install MongoDB via http://www.mongodb.org/downloads
# Linux: sudo apt-get install python-pip
# Linux Deps: pip install -U -r environment.txt
