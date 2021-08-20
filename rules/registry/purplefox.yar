rule purplefox
{
    meta:
        description = "remove purplefox registry"
        author = "syec"
        data = "20210818"
    strings:
        $1 = /Ms[0-9A-Z]{8}App\.dll/ wide ascii
    condition:
        $1
}