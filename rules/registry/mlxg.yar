rule mlxg_a
{
    meta:
        description = "remove mlxg_a registry"
        author = "syec"
        data = "20210818"
    strings:
        $1 = "KMSServerService" wide ascii
    condition:
        $1
}