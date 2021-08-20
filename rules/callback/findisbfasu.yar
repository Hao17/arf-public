rule findisbfasu_createprocess {
    strings:
        $s1 = {E9 64 F4 FF FF}
        $s2 = {48 3D FE 7F 00 00}
    condition:
        all of them
}

rule findisbfasu_loadimage {
    strings:
        $s1 = {75 11}
        $s2 = {74 0C}
        $s3 = {E8 07 00 00 00 00}
    condition:
        all of them
}
