#!/usr/bin/env python3

import argparse
import os
import sys
import puremagic as magic
from colorama import Fore, Style, init
import yara
from androguard.core.bytecodes.apk import APK
from prettytable import PrettyTable

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

def printStrings():
	
	string_tables = PrettyTable()
	string_tables.field_names = [Fore.GREEN + "String Col 1" + Fore.WHITE, Fore.RED + "String Col 2" + Fore.WHITE, Fore.YELLOW + "String Col 3" + Fore.WHITE]
	string_file = open("string.txt")
	string_data = string_file.read()
	onlyfiles = []
	switch = 0
	tmp_string = []

	for dirpath, dirs, files in os.walk("CommonStrings/"):  
		for filename in files:

			if(".txt" in filename):
				onlyfiles.append(os.path.join(dirpath,filename))

	for i in onlyfiles:
			
		tmp_file = open(i)

		myline = tmp_file.readline()
		while myline:
			myline = tmp_file.readline()
			#print(myline)
			if(myline.replace("\n", "") in string_data and myline != ""):
				if(switch == 0):
					tmp_string.append(myline.replace("\n", ""))
					switch = 1
				elif(switch == 1):
					tmp_string.append(myline.replace("\n", ""))
					switch = 2
				else:

					tmp_string.append(myline.replace("\n", ""))
					switch = 0
					string_tables.add_row(tmp_string)
					tmp_string = []
		tmp_file.close()

	string_file.close()
	
	print(string_tables)

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
		
		output = os.system("strings --all "+ args.strings + "> string.txt")
		printStrings()
	
	elif(args.analyze):
		
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
