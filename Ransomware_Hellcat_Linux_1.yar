rule Ransomware_Hellcat_Linux_1 {
	
	meta:
		author = "Dootix"
		date = "2025-02-02"
		version = "1.0"
		description = "Rule for Hellcat ransomware detection (Linux variant)."
		reference = "https://bazaar.abuse.ch/sample/6ef9a0b6301d737763f6c59ae6d5b3be4cf38941a69517be0f069d0a35f394dd"
		hash = "6ef9a0b6301d737763f6c59ae6d5b3be4cf38941a69517be0f069d0a35f394dd"
		
	strings:
		// Ransomware MXML config strings:
		$s1 = "All of your VM disks(*.vmdk) are Encrypted and Critical data was leaked" fullword ascii
		$s2 = "How to recover? Download the Qtox chat:https://qtox.github.io and contact us" fullword ascii
		$s3 = "<cmd>touch a</cmd>" fullword ascii
		
		// Function names:
		$s4 = "cry_thread" fullword ascii
		$s5 = "walk_thread" fullword ascii
		
		// Other:
		$s6 = "Readme.%s.txt" fullword ascii
		$s7 = "Encrypted->%s" fullword ascii
		$s8 = "/dev/urandom" fullword ascii
		
	condition:
		(uint32(0) == 0x464c457f and filesize < 500KB) and all of them
		

}
