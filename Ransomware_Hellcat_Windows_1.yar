rule Ransomware_Hellcat_Windows_1 {
	
	meta:
		author = "Dootix"
		date = "2025-02-11"
		version = "1.0"
		description = "Rule for Hellcat ransomware detection (Windows variant)."
		hash = "5b492a70c2bbded7286528316d402c89ae5514162d2988b17d6434ead5c8c274"
		
	strings:
		// Ransomware notes:
		$s1 = "Your network has been breached and all data were encrypted." fullword ascii
		$s2 = "We have already downloaded a huge amount of critical data." fullword ascii
		$s3 = "_README_.txt" fullword wide
		
		// Targeted extensions:
		$s4 = ".dll.sys.exe.drv.com.cat" fullword wide
		
		// Hex signatures:
		$hex1 = { 0C 0E 0E 0D 0B 0A 0F 0F 0C 0A 0D 45 00 00 00 00 }
		$hex2 = { AD AD BC CD FB DA F9 F8 F4 F6 F5 F4 F3 F6 F1 F0 }
		
	condition:
		(uint16(0) == 0x5a4d and filesize < 100KB) and all of them
		

}
