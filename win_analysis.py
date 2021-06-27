#!/usr/bin/python3

import sys
from prettytable import PrettyTable
import pefile
from colorama import Fore, Style, init



pe = pefile.PE(sys.argv[1])

#pe.print_info()

data_table = PrettyTable()
data_table.field_names = [Fore.YELLOW + "General info" + Fore.WHITE, Fore.BLUE + "Sections" + Fore.WHITE]

info_table = PrettyTable()
info_table.field_names = [Fore.GREEN + "Property" + Fore.WHITE, Fore.RED + "Value" + Fore.WHITE]

info_table.add_row(["Magic : ", hex(pe.OPTIONAL_HEADER.Magic)])

# Check if it is a 32-bit or 64-bit binary
if hex(pe.OPTIONAL_HEADER.Magic) == '0x10b':
    info_table.add_row(["Architecture","32-bit binary"])
elif hex(pe.OPTIONAL_HEADER.Magic) == '0x20b':
    info_table.add_row(["Architecture","64-bit binary"])
    
info_table.add_row(["Signature : ", hex(pe.NT_HEADERS.Signature)])
info_table.add_row(["TimeDateStamp : ", pe.FILE_HEADER.dump_dict()['TimeDateStamp']['Value'].split('[')[1][:-1]])
info_table.add_row(["NumberOfSections : ", hex(pe.FILE_HEADER.NumberOfSections)])
info_table.add_row(["Characteristics flags : ", hex(pe.FILE_HEADER.Characteristics)])
info_table.add_row(["ImageBase : ", hex(pe.OPTIONAL_HEADER.ImageBase)])
info_table.add_row(["SectionAlignment : ", hex(pe.OPTIONAL_HEADER.SectionAlignment)])
info_table.add_row(["FileAlignment : ", hex(pe.OPTIONAL_HEADER.FileAlignment)])
info_table.add_row(["SizeOfImage : ", hex(pe.OPTIONAL_HEADER.SizeOfImage)])
info_table.add_row(["DllCharacteristics flags : ", hex(pe.OPTIONAL_HEADER.DllCharacteristics)])

section_table = PrettyTable()
section_table.field_names = [Fore.GREEN + "Property" + Fore.WHITE, Fore.RED + "Value" + Fore.WHITE]


for section in pe.sections:
	section_table.add_row([" ----- "," ----- "])
	section_table.add_row([" "," "])
	section_table.add_row(["Section",section.Name.decode().rstrip('\x00')])
	section_table.add_row([" "," "])
	section_table.add_row(["Vitual Size",hex(section.Misc_VirtualSize)])
	
	section_table.add_row(["Virutal Address",hex(section.VirtualAddress)])
	
	section_table.add_row(["Size of raw data",hex(section.SizeOfRawData)])
	
	section_table.add_row(["Pointer to raw data",hex(section.PointerToRawData)])
	
	section_table.add_row(["Characterisitcs",hex(section.Characteristics)])
	section_table.add_row([" "," "])
data_table.add_row([info_table,section_table])
print(data_table)