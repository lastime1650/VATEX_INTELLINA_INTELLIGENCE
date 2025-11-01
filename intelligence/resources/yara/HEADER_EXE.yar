rule PE_Header_MZ
{
    meta:
        author = "user"
        description = "Detect files with MZ (PE) header at the start"
        date = "2025-11-02"

    strings:
        $mz_header = { 4D 5A }  // 'MZ' signature

    condition:
        $mz_header at 0
}
