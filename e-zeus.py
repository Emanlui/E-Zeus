#!/usr/bin/env python3

import argparse
import os
import sys
import puremagic as magic
from colorama import Fore, Style, init
import yara
from androguard.core.bytecodes.apk import APK


def yaraAnalysis(file_to_analyze):

	onlyfiles = []

	for dirpath, dirs, files in os.walk("YaraRules/"):  
		for filename in files:

			if(".yar" in filename or ".rule" in filename):
				onlyfiles.append(os.path.join(dirpath,filename))
			

	match = ""

	for i in onlyfiles:
		rules = yara.compile(i)
		temp_match = rules.match(file_to_analyze)
		if temp_match != []:
			for i in temp_match:
				match =	match + "\n" + str(i)
		
	print(match)

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

def analyze(file_to_analyze):

	type_of_the_file = str(magic.magic_file(file_to_analyze))

	# Windows Analysis
	if "Windows Executable" in type_of_the_file or ".msi" in type_of_the_file or ".dll" in type_of_the_file or ".exe" in type_of_the_file or ".drv" in type_of_the_file or ".sdb" in type_of_the_file or ".sys" in type_of_the_file or ".reg" in type_of_the_file:
		print(Fore.GREEN + '--- Analyzing Windows executable ---'+Fore.WHITE)
		yaraAnalysis(file_to_analyze)
		
	elif ".xltx" in type_of_the_file or ".xlam" in type_of_the_file or ".docm" in type_of_the_file or ".dotx" in type_of_the_file or ".pptm" in type_of_the_file or ".xlsm" in type_of_the_file or ".ppt" in type_of_the_file or ".doc" in type_of_the_file or ".xla" in type_of_the_file:
		print(Fore.GREEN + 'Analyzing Windows document...'+Fore.WHITE)		

def zeus(args):

	if(args.strings):
		print("strings")
		os.system("strings --all "+ args.strings)
	elif(args.analyze):
		print("analyze")
		print(args.analyze)
		analyze(args.analyze)
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
