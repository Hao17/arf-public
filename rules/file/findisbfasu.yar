import "hash"

rule findisbfasu
{
    meta:
        description = "findisbfasu"
    condition:
        hash.md5(0,filesize) == "ab4243eb960ed0029daf7bfd47ca78d8" 
}