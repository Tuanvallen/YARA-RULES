rule HSH_HashMaker_Identity
{
    meta:
        author = "tuan"
        description = "Detects the HashMaker9000 banner"

    strings:
        $id = "HashMaker9000"

    condition:
        $id
}

rule HSH_HashMaker_IO
{
    meta:
        author = "tuan"
        description = "Detects input and output strings used by HashMaker9000"

    strings:
        $prompt = "Enter string:"
        $fmt_in = "%199s"
        $fmt_out = "Hash: %u"

    condition:
        all of them
}

rule HSH_HashMaker_SourceArtifacts
{
    meta:
        author = "tuan"
        description = "Detects source code artifacts and internal function names"

    strings:
        $src = "hsh.c"
        $func = "fake_hash"
        $build = "completed.0"

    condition:
        any of them
}

rule HSH_HashMaker_CompilerSignature
{
    meta:
        author = "tuan"
        description = "Detects GCC Debian compiler signature used for this binary"

    strings:
        $gcc = "GCC: (Debian 15.2.0-7)"
        $glibc = "GLIBC_2.38"

    condition:
        all of them
}
