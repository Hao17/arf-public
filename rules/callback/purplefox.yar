rule pf_registry_callback {
    strings:
        $s1 = {E8 0F EB FF FF}
        $s2 = {E9 AF 00 00 00}
        $s3 = {7F 60}
        $s4 = {74 1D}
    condition:
        all of them
}