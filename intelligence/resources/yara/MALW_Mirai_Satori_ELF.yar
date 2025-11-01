private rule is_Mirai_gen7 {
    strings:
        $hexsts01 = { 68 7f 27 70 60 62 73 3c 27 28 65 6e 69 28 65 72 }
        $hexsts02 = { 74 7e 65 68 7f 27 73 61 73 77 3c 27 28 65 6e 69 }
    condition:
        all of them
}

private rule is_Mirai_Satori_gen {
    strings:
        $st08 = "tftp -r satori" fullword nocase wide ascii
        $st09 = "/bins/satori" fullword nocase wide ascii
        $st10 = "satori" fullword nocase wide ascii
        $st11 = "SATORI" fullword nocase wide ascii
    condition:
        2 of them
}

rule Mirai_Satori {
    strings:
        $mz = { 7F 45 4C 46 }   // ELF magic bytes
        $hexsts01 = { 63 71 75 ?? 62 6B 77 62 75 }
        $hexsts02 = { 53 54 68 72 75 64 62 }
        $hexsts03 = { 28 63 62 71 28 70 66 73 64 6F 63 68 60 } 
    condition:
        $mz at 0
        and all of ($hexsts01, $hexsts02, $hexsts03)
        and is_Mirai_gen7
        and is_Mirai_Satori_gen
        and filesize < 100KB
}
