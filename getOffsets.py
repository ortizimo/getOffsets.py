#!/usr/bin/env python3
# author:	Saulo Sal Ortiz
# date:		20260805
# updated: 	20261005
# version:	1.1
# desc:		checks PE file identifying offsets
# note: 	this is a work-in process. output may be incorrect // also as global-cli

import os
import struct
import sys

# official MS PE Subsystem Type table
SUBSYSTEM_TYPES = {
	0: "UNKNOWN (Unknown Subsystem)",
	1: "NATIVE (Device drivers and native Windows (BOOT) process)",
	2: "WINDOWS_GUI (Windows Graphical User Interface)",
	3: "WINDOWS_CUI (Windows Command-line/Console User Interface)",
	5: "OS2_CUI (OS/2 Console subsystem)",
	7: "POSIX_CUI (Legacy Unix Layer)",
	8: "NATIVE_WINDOWS (Legacy Win9x Driver)",
	9: "WINDOWS_CE_GUI (Windows CE / Mobile subsystem)",
	10: "EFI_APPLICATION (UEFI Extensible Firmware Interface App / Bootloader)",
	11: "EFI_BOOT_SERVICE_DRIVER (EFI Boot Service Driver)",
	12: "EFI_RUNTIME_DRIVER (EFI Runtime Driver)",
	13: "EFI_ROM (EFI ROM Image)",
	14: "XBOX (XBOX Console Subsystem)",
	16: "WINDOWS_BOOT_APPLICATION (Boot App)"
}
#Windows Mapping Table
WINDOWS_VERSION_MAP = {
	(0, 0): "Fields are zeroed. This binary was configured to accept any generic NT platform",
	(3, 10): "Windows NT 3.1 (NT Kernel 3.10)",
	(3, 50): "Windows NT 3.5 (NT Kernel 3.50)",
	(3, 51): "Windows NT 3.51 (NT Kernel 3.51)",
	(4, 0): "Windows 95 / Windows NT 4.0 (NT Kernel 4.00)",
	(4, 10): "Windows 98 (NT Kernel 4.10)",
	(4, 90): "Windows Me (NT Kernel 4.90)",
	(5, 0): "Windows 2000 / Server 2000 (NT Kernel 5.00)",
	(5, 1): "Windows XP (32bit) (NT Kernel 5.01)",
	(5, 2): "Windows XP (64bit) / Server 2003 (NT Kernel 5.02)",
	(6, 0): "Windows Vista /Server 2008 (NT Kernel 6.00)",
	(6, 1): "Windows 7 / Server 2008 R2 (NT Kernel 6.01)",
	(6, 2): "Windows 8 / Server 2012 (NT Kernel 6.02)",
	(6, 3): "Windows 8.1 / Server 2012 R2 (NT Kernel 6.03)",
	(10, 0): "Windows 10/11/Server 2016+ (NT Kernel 10.00)"
}

def get_windows_name(major, minor):
	return WINDOWS_VERSION_MAP.get((major, minor), "Unknown Windows Build Variant")

def find_exact_offsets(file_path):
	try:
		with open(file_path, "rb") as f:

		# read the PE pointer from standard DOS location (0x3C)
			f.seek(0x3C)
			pe_base_offset = struct.unpack("<I", f.read(4))[0]

		# compute machine field 
			machine_offset = pe_base_offset + 2

			f.seek(machine_offset)
			raw_bytes = f.read(2)

		# navigate to Optional_Header (pe + 4)	
			optional_header_base = pe_base_offset + 24

		# compute structural target offsets
			magic_offset = optional_header_base
			major_os_offset = optional_header_base + 40
			minor_os_offset = optional_header_base + 42
			major_sub_offset = optional_header_base + 48 
			minor_sub_offset = optional_header_base + 50 
			subsystem_type_offset = optional_header_base + 68

		# extract and decode machine architecture field
			machine_val = struct.unpack("<H", f.read(2))[0]
			
			if machine_val == 0x8664:
				arch_label = "64bit (AMD64 / x64)"
			elif machine_val == 0x014C:
				arch_label = "32bit (i386 / x86)"
			else:
				arch_label = "Other / Unknown"

		# magic field (32bit or 64bit PE file identification)
			f.seek(magic_offset)
			magic_val = struct.unpack("<H", f.read(2))[0]
			
			if magic_val == 0x010B:
				magic_str = "32bit (PE32)"
			elif magic_val == 0x020B:
				magic_str = "64bit (PE32+)"
			else:
				magic_str = f"Unknown Architecture (0x{magic_val:04X})"

		# extract Version integers
			f.seek(major_os_offset)
			major_os = struct.unpack("<H", f.read(2))[0]
			
			f.seek(minor_os_offset)
			minor_os = struct.unpack("<H", f.read(2))[0]
			
			f.seek(major_sub_offset)
			major_sub = struct.unpack("<H", f.read(2))[0]
			
			f.seek(minor_sub_offset)
			minor_sub = struct.unpack("<H", f.read(2))[0]

		# extract/decode Subsystem Type
			f.seek(subsystem_type_offset)
			subsystem_val = struct.unpack("<H", f.read(2))[0]
			subsystem_str = SUBSYSTEM_TYPES.get(subsystem_val, f"UNKNOWN_VALUE (0x{subsystem_val:04X})")

		# windows definitions
			target_os_name = get_windows_name(major_os, minor_os)
			target_sub_name = get_windows_name(major_sub, minor_sub)

		# clear terminal
			os.system('cls' if os.name == 'nt' else 'clear')

		# Output to screen				
			print("=" * 65)
			print("	 		GETOFFSETS v1.1 ")
			print("          (For ID/Editing PE Offsets with a HEX Editor)")
			print("=" * 65)
			print(f"[*] PE Header Starts at Absolute Offset: 0x{pe_base_offset:04X}")
			print(f"[*] Optional Header Starts at Offset:    0x{optional_header_base:04X}")
			print("=" * 65)
			print(f"[*] Machine Field Offset: 0x{machine_offset:X} | Value: 0x{machine_val:04X} ")
			print(f"[*] CPU Architecture: {arch_label}")
			print("=" * 65)
			print(f"[*] Magic Field Offset: 0x{magic_offset:04X} | Value: 0x{magic_val:04X}")
			print(f"[*] PE Binary Architecture: 0x{magic_str}")
			print("=" * 65)
			print(f"[*] OS Major Version Offset: 0x{major_os_offset:04X} | Value: {major_os}")
			print(f"[*] OS Minor Version Offset: 0x{minor_os_offset:04X} | Value: {minor_os}")
			print(f"[*] Target OS: {target_os_name}")
			print("=" * 65)
			print(f"[*] Min Runtime Major Offset: 0x{major_sub_offset:04X} | Value: {major_sub}")
			print(f"[*] Min Runtime Minor Offset: 0x{minor_sub_offset:04X} | Value: {minor_sub}")
			print(f"[*] Min API Framework: {target_sub_name}")
			print("=" * 65)
			print(f"[*] Subsystem Type Offset: 0x{subsystem_type_offset:04X} | Raw Value: {subsystem_val}")
			print(f"[*] Subsystem Type: {subsystem_str}")
			print("=" * 65)
			print("Note: Output may be incorrect...script is a work-in-progress.\n")
		# --------------------------	

# default error code
	except FileNotFoundError:
		print(f"Error: File '{file_path}' not found.")
	except Exception as e:
		print(f"An error occurred: {e}")
		
if __name__ == "__main__":
	if len(sys.argv) < 2:
		print("Usage: python3 <script.py> <file>")
	else:
		find_exact_offsets(sys.argv[1])

				
			
			
			
			
			
			
	
	
	
	
	
	
	
	
		
			
