rule Yomo_FileInspector_Identity
{
    meta:
        description = "Detects the main identity string of the FileInspector tool"
        author = "tuan"

    strings:
        $id = "FileInspector Tool"

    condition:
        $id
}

rule Yomo_FileInspector_PromptError
{
    meta:
        description = "Detects user interaction strings used by FileInspector"
        author = "tuan"

    strings:
        $prompt = "Enter filename:"
        $error  = "Error opening file."

    condition:
        all of ($prompt, $error)
}

rule Yomo_FileInspector_SourceArtifact
{
    meta:
        description = "Detects embedded source filename and debug artifact"
        author = "tuan"

    strings:
        $src = "yomo.c"
        $tag = "completed.0"  // build artifact from gcc

    condition:
        any of them
}

rule Yomo_FileInspector_CompilerSignature
{
    meta:
        description = "Detects Debian GCC build signature used to compile the binary"
        author = "tuan"

    strings:
        $gcc_ver = "GCC: (Debian 15.2.0-7)"
        $glibc   = "GLIBC_2.38"

    condition:
        all of them
}
