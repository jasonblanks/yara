rule ScriptsWithinCompressedFiles
{
	strings:
		////windows natively supported http://kb.winzip.com/kb/entry/254/
		// // $_archive_extention_zip = ".zip" // alt: zipx
		// $_archive_magicnumber_string_zip = "PK"
		$_archive_magicnumber_hex_zip1 = {50 4b 03 04}
		$_archive_magicnumber_hex_zip2 = {50 4b 05 06}
		$_archive_magicnumber_hex_zip3 = {50 4b 07 08}

		////winzip additional
		// $_archive_extention_ar= ".tar"
		$_archive_magicnumber_hex_tar1 = {75 73 74 61 72}
		$_archive_magicnumber_hex_tar1 = {66 69 6C 65 73 2F}  // "files/" this may need a second look
	
		// $_archive_magicnumber_string_tar1 = "ustar"

		// $_archive_extention_ar= ".rar"
		// $_archive_magicnumber_string_rar1 = "RE~^"
		// $_archive_magicnumber_string_rar2 = "Rar!"
		$_archive_magicnumber_hex_rar1 = {52 45 7E 5E}
		$_archive_magicnumber_hex_rar2 = {52 61 72 21 1A 07}

		// $_archive_extention_ar= ".iso"
		// $_archive_magicnumber_string_iso = "CD001"
		$_archive_magicnumber_hex_iso = {43 44 30 30 31}

		// $_archive_extention_gz = ".gz"
		$_archive_magicnumber_hex_gz1 = {1F 8B 08}  // file table appears non ascii

		// $_archive_extention_cab= ".cab"
		// $_archive_magicnumber_string_cab = "MSCF"
		$_archive_magicnumber_hex_cab = {4D 53 43 46}

		// $_archive_extention_compress= ".z"
		$_archive_magicnumber_hex_compress = {1F 9D}  // Doesnt appear to have a plain text file table

		// $_archive_extention_xz= ".xz"
		$_archive_magicnumber_hex_xz = {FD 37 7A 58 5A 00}

		// $_archive_extention_lzh= ".lzh" //lza - lzh most likly not this ext though
		$_archive_magicnumber_hex_lzh = {1F A0}

		// $_archive_extention_arc= ".arc"
		// $_archive_magicnumber_string_arc = "01Ah"      // ?http://www.fileformat.info/format/arc/corion.htm
		$_archive_magicnumber_hex_arc = {41 72 43 01}  // FreArc
		$_archive_magicnumber_hex_arc = {30 31 41 68}  // above

		// $_archive_extention_arc= ".arj"
		$_archive_magicnumber_hex_arj1 = {60 EA}
		$_archive_magicnumber_hex_arj2 = {EA 60}

		////7zip additional
		// http://www.7-zip.org/history.txt
		//https://sevenzip.osdn.jp/chm/general/formats.htm

		// $_archive_extention_7z = ".7z"
		// $_archive_magicnumber_string_7z = "7z¼¯'" 
		$_archive_magicnumber_hex_7z = {37 7A BC AF 27 1C}  // file table appears non ascii

		// $_archive_extention_ar= ".ar" // alt: .a,.ar,.lib
		// $_archive_magicnumber_string_ar1 = "<ar>" // System V Release 1 ar archive
		// $_archive_magicnumber_string_ar1 = "!<arch>" // current ar archive
		$_archive_magicnumber_hex_ar1 = {21 3C 61 72 63 68 3E 0A}
		$_archive_magicnumber_hex_ar2 = {3d 3c 61 72 3e}


		// $_archive_extention_dmg = ".dmg"
		// $_archive_magicnumber_string_dmg = "x.s.bb`" 
		$_archive_magicnumber_hex_dmg = {78 01 73 0D 62 62 60}

		// $_archive_extention_bz2 = ".bz2"
		// $_archive_magicnumber_string_bz2 = "BZh"
		$_archive_magicnumber_hex_bz2 ={42 5A 68}


		//all others
		// $_archive_extention_cpio = ".cpio"
		// $_archive_magicnumber_string_cpio1 = "070701"  // SVR4 cpio
		// $_archive_magicnumber_string_cpio2 = "070702"  // "crc" cpio
		// $_archive_magicnumber_string_cpio3 = "070707"  // consider just using "07070"
		$_archive_magicnumber_hex_cpio = {30 37 30 37 30}

		// $_archive_extention_shar = ".shar"  // no other identifier

		// $_archive_extention_lbr = ".lbr"
		// $_archive_magicnumber_string_lbr1 = "0           00"  // needs validation

		// $_archive_extention_zoo = ".zoo"
		$_archive_magicnumber_hex_zoo1 = {fd c4 a7 dc}

		//Compression only
		// $_archive_extention_bz = ".bz"
		// $_archive_magicnumber_string_bz = "BZ"
		$_archive_magicnumber_hex_lz = {42 5a}

		// $_archive_extention_lz = ".lz"
		// $_archive_magicnumber_string_lz = "LZIP"
		$_archive_magicnumber_hex_lz = {4C 5A 49 50}  // file table appears non ascii
		
		// $_archive_extention_lzo = "tar.lzo"
		// $_archive_magicnumber_string_lzo = "LZO"
		$_archive_magicnumber_hex_lzo = {89 4C 5A 4F}
		
		// $_archive_extention_lzo = "tar.xz"
		$_archive_magicnumber_hex_xz = {FD 37 7A 58 5A}
		
		// $_archive_extention_lzo = ".lzma"
		$_archive_magicnumber_hex_lzma = {5D 00 00}
		

		//Scripting Langueges
		$_scripting_extention = ".vbs"
		$_scripting_extention = ".js"
		$_scripting_extention = ".vb"
		$_scripting_extention = ".wwb"
		$_scripting_extention = ".pls"
		$_scripting_extention = ".pl"
		$_scripting_extention = ".p"
		$_scripting_extention = ".nsf"
		$_scripting_extention = ".rxs"
		$_scripting_extention = ".rx"
		$_scripting_extention = ".rex"
		$_scripting_extention = ".pys"
		$_scripting_extention = ".pyw"
		$_scripting_extention = ".py"
		$_scripting_extention = ".tcls"
		$_scripting_extention = ".phps"
		$_scripting_extention = ".rbs"
		$_scripting_extention = ".xcs"
		$_scripting_extention = ".lua"
		$_scripting_extention = ".xml"  //consider removing
		$_scripting_extention = ".kix"
		$_scripting_extention = ".ns"
		$_scripting_extention = ".92bs"
		$_scripting_extention = ".48s"
		$_scripting_extention = ".cfxb"
		$_scripting_extention = ".scsb"

		// Not listed for wsh, but commonly seen
		$_scripting_extention = ".bat"
		$_scripting_extention = ".ps"
		$_scripting_extention = ".ps1"
		$_scripting_extention = ".ps1xml"
		$_scripting_extention = ".psc1"
		$_scripting_extention = ".ps2"
		$_scripting_extention = ".ps2xml"
		$_scripting_extention = ".psc2"
		$_scripting_extention = ".msh"  //Monad script later renamed to powershell
		$_scripting_extention = ".msh1"
		$_scripting_extention = ".msh2"
		$_scripting_extention = ".mshxml"
		$_scripting_extention = ".msh1xml"
		$_scripting_extention = ".msh2xml"
		$_scripting_extention = ".wsf"
		$_scripting_extention = ".tcl"
		$_scripting_extention = ".plf"

		$_scripting_extention = ".jar"
		$_scripting_extention = ".msi"
		$_scripting_extention = ".cmd"
		$_scripting_extention = ".vbe"
		$_scripting_extention = ".jse"
		$_scripting_extention = ".wsf"
		$_scripting_extention = ".ws"
		$_scripting_extention = ".wsc"
		$_scripting_extention = ".wsh"
		$_scripting_extention = "."

		// yes i get it, consider commenting out a few as to not blow up storage
		$_scripting_extention = ".jar"
		$_scripting_extention = ".msc"
		$_scripting_extention = ".cpl"
		$_scripting_extention = ".hta"
		$_scripting_extention = ".scr"
		$_scripting_extention = ".com"
		$_scripting_extention = ".msp"
		$_scripting_extention = ".msi"
		$_scripting_extention = ".gadget"
		$_scripting_extention = ".application"

		// Questionable extensions
		$_scripting_extention = ".swf"
		$_scripting_extention = ".dll"
		$_scripting_extention = ".sys"
		$_scripting_extention = ".shs"
		$_scripting_extention = ".lnk"
		$_scripting_extention = ".wmf"
		$_scripting_extention = ".chm"
		$_scripting_extention = ".ocx"  //activeX control
		$_scripting_extention = ".xlm" //excel macro
		$_scripting_extention = ".drv"
		$_scripting_extention = ".dev"
		$_scripting_extention = ".cpl"
		$_scripting_extention = ".pif"
		$_scripting_extention = ".hlp"
		$_scripting_extention = ".reg"
		$_scripting_extention = ".scf"
		$_scripting_extention = ".inf"
		$_scripting_extention = ".chm"
		$_scripting_extention = ".sct"
		$_scripting_extention = ".cpl"
		$_scripting_extention = ".cmd"
		$_scripting_extention = ".mst"
		$_scripting_extention = ".reg"
		$_scripting_extention = ".shb"
		$_scripting_extention = ".pif"



		//Lone macro files
		$_scripting_extention = ".docm"
		$_scripting_extention = ".dotm"
		$_scripting_extention = ".xlsm"
		$_scripting_extention = ".xltm"
		$_scripting_extention = ".xlam"
		$_scripting_extention = ".pptm"
		$_scripting_extention = ".ppam"
		$_scripting_extention = ".ppsm"
		$_scripting_extention = ".sldm"

	condition:
		(for any of ($_archive_magicnumber_hex*) : ( $ at 0 )) and (1 of ($_scripting_extention*))
}
