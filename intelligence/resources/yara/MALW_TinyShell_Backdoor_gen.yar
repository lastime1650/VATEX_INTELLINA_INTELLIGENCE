/* TinyShell backdoor detection for ELF or MachO */
rule MALW_TinyShell_backconnect_Gen {
    meta:
        description = "Detects TinyShell backdoor on ELF or MachO binaries"
        date = "2018-02-11"
        author = "@unixfreaxjp"

    strings:
        // priv01
        $priv01_1 = { 73 3A 70 3A 00 }
        $priv01_2 = "Usage: %s" fullword nocase wide ascii
        $priv01_3 = "[ -s secret ]" fullword nocase wide ascii
        $priv01_4 = "[ -p port ]" fullword nocase wide ascii

        // priv02
        $priv02_1 = "socket" fullword nocase wide ascii
        $priv02_2 = "connect" fullword nocase wide ascii
        $priv02_3 = "alarm" fullword nocase wide ascii
        $priv02_4 = "dup2" fullword nocase wide ascii
        $priv02_5 = "execl" fullword nocase wide ascii
        $priv02_6 = "openpty" fullword nocase wide ascii
        $priv02_7 = "putenv" fullword nocase wide ascii
        $priv02_8 = "setsid" fullword nocase wide ascii
        $priv02_9 = "ttyname" fullword nocase wide ascii
        $priv02_0 = "waitpid" fullword nocase wide ascii
        $priv02_c1 = "HISTFIL" fullword nocase wide ascii
        $priv02_c2 = "TERML" fullword nocase wide ascii
        $priv02_c3 = "/bin/sh" fullword nocase wide ascii

        // priv03
        $priv03_1 = { 41 57 41 56 41 55 41 54 55 53 0F B6 06 }
        $priv03_2 = { 48 C7 07 00 00 00 00 48 C7 47 08 00 00 }
        $priv03_3 = { 55 48 89 E5 41 57 41 56 41 55 41 54 53 }
        $priv03_4 = { 55 48 89 E5 48 C7 47 08 00 00 00 00 48 }

        // priv04
        $priv04_1 = { 89 DF E8 FB A4 FF FF 83 C3 01 81 FB 00 04 }
        $priv04_2 = { 66 89 05 7D 5E 00 00 }

    condition:
        // ELF or OSX check
        (uint32(0) == 0x7f454c46 or
         uint32(0) == 0xfeedface or uint32(0) == 0xcafebabe or
         uint32(0) == 0xbebafeca or uint32(0) == 0xcefaedfe or
         uint32(0) == 0xfeedfacf or uint32(0) == 0xcffaedfe)
         
        // priv01: all
        and all of ($priv01_*) 

        // priv02: 5 of vare* or 2 of varc*
        and (5 of ($priv02_1, $priv02_2, $priv02_3, $priv02_4, $priv02_5, $priv02_6, $priv02_7, $priv02_8, $priv02_9, $priv02_0)
             or 2 of ($priv02_c1, $priv02_c2, $priv02_c3))

        // priv03: 2 of ($priv03_* )
        and 2 of ($priv03_1, $priv03_2, $priv03_3, $priv03_4)

        // priv04: 1 of ($priv04_* )
        and 1 of ($priv04_1, $priv04_2)

        // filesize limit
        and filesize < 100KB
}
