#!/usr/bin/env python3

import argparse
import os
import sys
from prettytable import PrettyTable
import puremagic as magic
from colorama import Fore, Style, init
import yara
from androguard.core.bytecodes.apk import APK

def deleteFiles():

	if(os.path.exists("hash.txt")):
		output = os.system("rm hash.txt")
	if(os.path.exists("string.txt")):
		output = os.system("rm string.txt")

def hashFile(file_to_analyze):

	data_table = PrettyTable()
	data_table.field_names = [Fore.YELLOW + "Hash type" + Fore.WHITE, Fore.BLUE + "Value" + Fore.WHITE]

	hash_type = ["sha1", "sha256","sha512","md5"]

	os.system("sha1sum "+ file_to_analyze + ">> hash.txt")
	os.system("sha256sum "+ file_to_analyze + ">> hash.txt")
	os.system("sha512sum "+ file_to_analyze + ">> hash.txt")
	os.system("md5sum "+ file_to_analyze + ">> hash.txt")

	with open("hash.txt") as f:
		content = f.readlines()

	for pos in range(0,4):
		hash_value = content[pos].split(" ")
		data_table.add_row([hash_value[0],hash_type[pos]])

	print(data_table)

def yaraAnalysis(file_to_analyze):

	data_table = PrettyTable()
	data_table.field_names = [Fore.YELLOW + "Path of the rule" + Fore.WHITE, Fore.BLUE + "Rule" + Fore.WHITE]

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
			for j in temp_match:
				data_table.add_row([i,str(j)])
				
		
	print(data_table)

def setupParser():
	args = []
	parser = argparse.ArgumentParser()

	parser.add_argument("-y","--yara", required=False, help="Checks if some yara rule matches the file pass by argument.", type=str)

	parser.add_argument("-s","--strings", required=False, help="Get the strings from the file.", type=str)

	parser.add_argument("-a","--analyze", required=False, help="Analyze the file.", type=str)

	parser.add_argument("-mf","--multifile", required=False, nargs='+', help="Analyze multiple files.")

	parser.add_argument("-d","--docs", required=False, help="Analyze document files.",type=str)

	parser.add_argument("-H","--hash",action='store_true', help="Scan the hash file.")

	parser.add_argument("-mh","--multihash", required=False, nargs='+', help="Scan multiple hashes.", type=list)

	parser.add_argument("-m","--metadata", required=False, help="Get metadata information.", type=str)

	parser.add_argument("-dm","--domain", required=False, help="Extract URLs and IPs.", type=str)

	parser.add_argument('-v', '--verbose',action='store_true',help='Verbose Output')

	args = parser.parse_args()
	return args 



def analyze(file_to_analyze):

	type_of_the_file = str(magic.magic_file(file_to_analyze))

	# Windows Analysis
	if "Windows Executable" in type_of_the_file or ".msi" in type_of_the_file or ".dll" in type_of_the_file or ".exe" in type_of_the_file or ".drv" in type_of_the_file or ".ocx " in type_of_the_file or ".sys" in type_of_the_file or ".cpl " in type_of_the_file or ".scr" in type_of_the_file:
		print(Fore.GREEN + '--- Analyzing Windows executable ---'+Fore.WHITE)
		#yaraAnalysis(file_to_analyze)
		command = "python3 win_analysis.py " + file_to_analyze
		os.system(command)
		
	elif ".xltx" in type_of_the_file or ".xlam" in type_of_the_file or ".docm" in type_of_the_file or ".dotx" in type_of_the_file or ".pptm" in type_of_the_file or ".xlsm" in type_of_the_file or ".ppt" in type_of_the_file or ".doc" in type_of_the_file or ".xla" in type_of_the_file:
		print(Fore.GREEN + 'Analyzing Windows document...'+Fore.WHITE)		

def zeus(args):
	
	if(args.strings):
		output = os.system("strings --all "+ args.strings + "> string.txt")
		if(args.verbose):
			command = "python3 strings.py v"
			os.system(command)
			if(args.hash):
				hashFile(args.strings)
		elif (args.hash):
			command = "python3 strings.py s"
			os.system(command)
			hashFile(args.strings)
		else:
			command = "python3 strings.py s"
			os.system(command)
	elif(args.analyze):
		analyze(args.analyze)
		if(args.hash):
			hashFile(args.analyze)
	elif(args.yara):
		yaraAnalysis(args.yara)
		if(args.hash):
			hashFile(args.yara)
	elif(args.multifile):
		print("multifile")
	elif(args.docs):
		print("docs")
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
	
	#os.system("python3 dependencies/ascii.py")
	args = setupParser()
	zeus(args)
	deleteFiles()
