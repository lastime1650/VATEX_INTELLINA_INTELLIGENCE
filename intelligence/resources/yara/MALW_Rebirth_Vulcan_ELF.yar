rule MALW_Rebirth_Vulcan_ELF {
    meta:
        description = "Detects Rebirth Vulcan variant a Torlus NextGen MALW"
        date = "2018-01-21"

    strings:
        $spec01 = "vulcan.sh" fullword nocase wide ascii
        $spec02 = "Vulcan" fullword nocase wide ascii
        // ELF 매직바이트
        $mz = { 7F 45 4C 46 }

        // Rebirth strings
        $str01 = "/usr/bin/python" fullword nocase wide ascii
        $str02 = "nameserver 8.8.8.8\nnameserver 8.8.4.4\n" fullword nocase wide ascii
        $str03 = "Telnet Range %d->%d" fullword nocase wide ascii
        $str04 = "Mirai Range %d->%d" fullword nocase wide ascii
        $str05 = "[Updating] [%s:%s]" fullword nocase wide ascii
        $str06 = "rm -rf /tmp/* /var/* /var/run/* /var/tmp/*" fullword nocase wide ascii
        $str07 = "\x1B[96m[DEVICE] \x1B[97mConnected" fullword nocase wide ascii

        // Rebirth hex
        $hex01 = { 0D C0 A0 E1 00 D8 2D E9 }
        $hex02 = { 3C 1C 00 06 27 9C 97 98 }
        $hex03 = { 94 21 EF 80 7C 08 02 A6 }
        $hex04 = { E6 2F 22 4F 76 91 18 3F }
        $hex05 = { 06 00 1C 3C 20 98 9C 27 }
        $hex06 = { 55 89 E5 81 EC ?? 10 00 }
        $hex07 = { 55 48 89 E5 48 81 EC 90 }
        $hex08 = { 6F 67 69 6E 00 }

        // Bot strings
        $bot01 = "MIRAITEST" fullword nocase wide ascii
        $bot02 = "TELNETTEST" fullword nocase wide ascii
        $bot03 = "UPDATE" fullword nocase wide ascii
        $bot04 = "PHONE" fullword nocase wide ascii
        $bot05 = "RANGE" fullword nocase wide ascii
        $bot06 = "KILLATTK" fullword nocase wide ascii
        $bot07 = "STD" fullword nocase wide ascii
        $bot08 = "BCM" fullword nocase wide ascii
        $bot09 = "NETIS" fullword nocase wide ascii
        $bot10 = "FASTLOAD" fullword nocase wide ascii

    condition:
        $mz at 0
        and all of ($spec01, $spec02)
        and 4 of ($str01, $str02, $str03, $str04, $str05, $str06, $str07)
        and 2 of ($hex01, $hex02, $hex03, $hex04, $hex05, $hex06, $hex07, $hex08)
        and 6 of ($bot01, $bot02, $bot03, $bot04, $bot05, $bot06, $bot07, $bot08, $bot09, $bot10)
        and filesize < 300KB
}
