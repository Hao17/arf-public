rule mlxg_a_createthread {
    strings:
        $s1 = {74 07}
        $s2 = {E8 28 E8 FF FF}
    condition:
        all of them
}

rule mlxg_a_loadimage {
    strings:
        $s1 = {74 07}
        $s2 = {E8 28 E8 FF FF}
    condition:
        all of them
}

rule mlxg_a_registry {
    strings:
        $s1 = {FF 15 30 22 00 00}
        $s2 = {0F 84 88 00 00 00}
        $s3 = {76 05}
        $s4 = {75 69}
    condition:
        all of them
}

rule mlxg_a_shutdown1 {
    strings:
        $s1 = {E8 AC 40 00 00}
        $s2 = {E8 98 40 00 00}
        $s3 = {FF 15 41 5B 00 00}
        $s4 = {FF 15 28 5B 00 00}
    condition:
        all of them
}

rule mlxg_a_shutdown2 {
    strings:
        $s1 = {E8 0B 07 00 00}
        $s2 = {E9 D2 01 00 00}
    condition:
        all of them
}

rule mlxg_b_createprocess1 {
    strings: 
        $s1 = {E8 06 E5 FF FF}
        $s2 = {75 51}
        $s3 = {74 2E}
        $s4 = {74 1D}
    condition:
        all of them
}

rule mlxg_b_createprocess2 {
    strings:
        $s1 = {FF 15 4B A0 00 00}
        $s2 = {0F 88 E3 00 00 00}
        $s3 = {0F 84 DB 00 00 00}
        $s4 = {FF 15 BA 9F 00 00}
    condition:
        all of them
}

rule mlxg_b_createthread {
    strings:
        $s1 = {74 07}
        $s2 = {E9 94 E5 FF FF}
    condition:
        all of them
}

rule mlxg_b_registry {
    strings:
        $s1 = {0F 84 0D 01 00 00}
        $s2 = {0F 85 01 01 00 00}
        $s3 = {0F 84 F4 00 00 00}
        $s4 = {76 09}
    condition:
        all of them
}

rule mlxg_b_shutdown {
    strings:
        $s1 = {FF 15 8F 4F 00 00}
        $s2 = {FF 15 79 4F 00 00}
        $s3 = {E8 C0 08 00 00}
        $s4 = {E8 37 00 00 00}
    condition:
        all of them
}