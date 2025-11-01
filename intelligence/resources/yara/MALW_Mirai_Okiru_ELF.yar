private rule is_Mirai_gen7 {
    strings:
        $hexsts01 = { 68 7f 27 70 60 62 73 3c 27 28 65 6e 69 28 65 72 }
        $hexsts02 = { 74 7e 65 68 7f 27 73 61 73 77 3c 27 28 65 6e 69 }
    condition:
        all of them
}

rule Mirai_Okiru {
    strings:
        $mz = { 7F 45 4C 46 }   // ELF magic bytes
    condition:
        $mz at 0
        and is_Mirai_gen7
        and filesize < 100KB
}
