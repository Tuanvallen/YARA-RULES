rule Pattern_HTTP_Downloader
{
    meta:
        description = "Mendeteksi pola HTTP downloader sederhana"
        author = "tuan"
    strings:
        $get  = "GET %s HTTP/1.1"
        $ua   = "User-Agent: SimpleClient/1.0"
        $conn = "Connection: close"
        $host = "Host: %s"
    condition:
        all of them
}

rule Pinterest_Downloader
{
    meta:
        description = "Deteksi file yang mendownload gambar dari i.pinimg.com"
        author = "tuan"
    strings:
        $domain = "i.pinimg.com"
        $path   = "/236x/b7/31/26/b7312644e40d0355303f0889cf6fb6d3.jpg"
        $outfile = "downloaded.jpg"
    condition:
        all of them
}

rule Nework_Error_Indicators
{
    meta:
        description = "Mendeteksi error messages khas downloader"
        author = "tuan"
    strings:
        $e1 = "Host lookup failed"
        $e2 = "Socket creation failed"
        $e3 = "Connection failed"
        $e4 = "File open failed"
    condition:
        any of them
}

rule Build_Metadata_Indicator
{
    meta:
        description = "Compiler & binary metadata (bukan malware, tapi fingerprint unik)"
        author = "tuan"
    strings:
        $comp1 = "GCC: (Debian 15.2.0-7) 15.2.0"
        $src   = "download.c"
        $tag   = "__abi_tag"
    condition:
        2 of ($comp1, $src, $tag)
}
