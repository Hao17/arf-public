import "hash"

rule mlxg_a
{
    meta:
        description = "mlxg_a"
        author = "syec"
        date = "20210819"
    condition:
        uint16(0) == 0x5a4d and filesize < 10000KB and (
        hash.md5(0,filesize) == "253b027556ba7048261b09dcb7ed1c7f" or
        hash.md5(0,filesize) == "062acdac0bed29b0049d48263bd7b169" or
        hash.md5(0,filesize) == "e6e2590ba5978b8297a6e630f424e7bc" or
        hash.md5(0,filesize) == "0a98900cf6d9546b1789a0d822b3c7c8" or
        hash.md5(0,filesize) == "c21df591eefd4ec978fd3488c6d1c673" or
        hash.md5(0,filesize) == "7d0e90ce1a84c92de9e8731ae3c567fc" or
        hash.md5(0,filesize) == "e8c4fd6e0f1a169d323ca3735f3488a9" or
        // c:\windows\kms10\kms10.exe
        hash.md5(0,filesize) == "173b6225d42be7ed01922f472a4bea18")
}

rule mlxg_b
{
    meta:
        description = "mlxg_b"
        author = "syec"
        date = "20210819"
    condition:
        // c:\windows\system32\drivers\lsanserver.sys *random name 51kb
        // c:\windows\system32\drivers\tnannel.sys *random name 56kb
        // c:\users\{user}\AppData\Local\Microsoft\Event Viewer\wccenter.exe
        // c:\users\{user}\AppData\Local\Microsoft\Event Viewer\wdlogin.exe
        // c:\users\{user}\AppData\Local\Microsoft\Event Viewer\wrme.exe
        // c:\users\{user}\AppData\Local\Microsoft\Event Viewer\wuhost.exe
        uint16(0) == 0x5a4d and filesize < 10000KB and (
        hash.md5(0,filesize) == "d7ab69fad18d4a643d84a271dfc0dbdf" or
        hash.md5(0,filesize) == "b2d43a8ab4803371b60479538c509cf0" or
        hash.md5(0,filesize) == "94a8dea1563590ff8b2f2b4cdc2308c9" or
        hash.md5(0,filesize) == "8a2122e8162dbef04694b9c3e0b6cdee" or
        hash.md5(0,filesize) == "7c529369f0899d3154b7979bbe17e280" or
        hash.md5(0,filesize) == "d2a66a9b1c9debb4ba1dc44e272cebae" or
        hash.md5(0,filesize) == "2fbf81ac940327678a449192a9920a05" or
        hash.md5(0,filesize) == "84e38c4e6a3b05db499f140b28637a82" )
}