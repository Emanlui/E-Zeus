#!/usr/bin/python3

from prettytable import PrettyTable
from colorama import Fore, Style, init
import os
import sys

def printAllStrings():
	alphabet = ['A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P','Q','R','S','T','U','V','W','X','Y','Z','a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z']

	string_tables = PrettyTable()
	string_tables.field_names = [Fore.GREEN + "Strings" + Fore.WHITE]
	
	switch = 0
	tmp_string = []

	strings_that_are_too_large_to_be_printed = []

	with open("string.txt") as f:
		content = f.readlines()

	for line in content:
			
		validation = False
		found = 0
		for letter in alphabet:
		

			if(letter in line):
				found = found + 1
			if(found > 7):
				validation = True
		if(validation):
			string_to_add = str(line.replace("\n", "").replace(","," "))
			strings_that_are_too_large_to_be_printed.append(string_to_add)
			string_tables.add_row([string_to_add])
				
	print(string_tables)


def printStrings():
	
	string_tables = PrettyTable()
	string_tables.field_names = [Fore.GREEN + "Strings" + Fore.WHITE, Fore.RED + "Strings" + Fore.WHITE, Fore.YELLOW + "Strings" + Fore.WHITE]
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

if(sys.argv[1] == "v"):
	printAllStrings()
else:
	printStrings()