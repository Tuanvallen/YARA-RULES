rule HashTool_CoreStrings
{
    meta:
        author = "tuan"
        description = "Mendeteksi string inti dari program HashMaker"

    strings:
        $s1 = "HashMaker9000"
        $s2 = "Enter string"
        $s3 = "Hash:"
        $s4 = "fake_hash"

    condition:
        any of ($s*)
}

rule HashTool_GlibcSymbols
{
    meta:
        author = "tuan"
        description = "Mendeteksi simbol-simbol GLIBC pada binary ELF"

    strings:
        $g1 = "GLIBC_2."
        $g2 = "GLIBC_"

    condition:
        any of ($g*)
}

rule HashTool_DebugBuild
{
    meta:
        author = "tuan"
        description = "Mengenali binary hasil build GCC dengan simbol debug"

    strings:
        $c1 = "GCC"
        $c2 = "hsh.c"
        $c3 = ".comment"

    condition:
        any of ($c*)
}

rule HashTool_ELFSections
{
    meta:
        author = "tuan"
        description = "Mendeteksi struktur ELF melalui section umum"

    strings:
        $e1 = ".dynsym"
        $e2 = ".text"
        $e3 = ".rodata"
        $e4 = ".interp"

    condition:
        any of ($e*)
}
