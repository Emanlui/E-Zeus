#!/usr/bin/env python3

import argparse
import os
import sys

def setupParser():
	args = []
	parser = argparse.ArgumentParser()

	parser.add_argument("-s","--strings", required=False, help="Get the strings from the file.", type=str)

	parser.add_argument("-a","--analyze", required=False, help="Analyze the file.", type=str)

	parser.add_argument("-mf","--multifile", required=False, nargs='+', help="Analyze multiple files.")

	parser.add_argument("-d","--docs", required=False, help="Analyze document files.",type=str)

	parser.add_argument("-H","--hash", required=False, help="Scan the hash file.", type=str)

	parser.add_argument("-mh","--multihash", required=False, nargs='+', help="Scan multiple hashes.", type=list)

	parser.add_argument("-m","--metadata", required=False, help="Get metadata information.", type=str)

	parser.add_argument("-dm","--domain", required=False, help="Extract URLs and IPs.", type=str)

	parser.add_argument('-v', '--verbose',action='store_true',help='Verbose Output')

	args = parser.parse_args()
	return args 


def zeus(args):

	if(args.strings):
		print("strings")
		os.system("strings --all "+ args.strings)
	elif(args.analyze):
		print("analyze")
		print(args.analyze)
	elif(args.multifile):
		print("multifile")
	elif(args.docs):
		print("docs")
	elif(args.hash):
		print("hash")
	elif(args.multihash):
		print("multihash")
	elif(args.metadata):
		print("metadata")
	elif(args.domain):
		print("domain")
	else:
		print("Error running the script")
		sys.exit(1)



if __name__ == "__main__":
	
	os.system("python3 dependencies/ascii.py")
	args = setupParser()
	zeus(args)
