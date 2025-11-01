private rule is_LinuxHttpsdStrings {
    strings:
        $st01 = "k.conectionapis.com" nocase
        $st02 = "key=%s&host_name=%s&cpu_count=%d&os_type=%s&core_count=%s" nocase
        $st03 = "id=%d&result=%s" nocase
        $st04 = "rtime" nocase
    condition:
        all of them
}

rule Linux_Httpsd_malware_ARM {
    strings:
        $hexsts01 = { f0 4f 2d e9 1e db 4d e2 ec d0 4d e2 01 40 a0 e1 }
        $hexsts02 = { f0 45 2d e9 0b db 4d e2 04 d0 4d e2 3c 01 9f e5 }
        $hexsts03 = { f0 45 2d e9 01 db 4d e2 04 d0 4d e2 bc 01 9f e5 }
    condition:
        all of ($hexsts*) and is_LinuxHttpsdStrings
}
