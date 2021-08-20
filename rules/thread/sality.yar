import "hash"

rule sality_bh
{
    meta:
        description = "sality_bh"
        author = "syec"
        date = "20210729"
    condition:
        hash.md5(0,filesize) == "bd9d7f7b9f898963a46971200b920454" or
        hash.md5(0,filesize) == "ee9ff48de3c35b0b265d07ff5b7a2c39" or
        hash.md5(0,filesize) == "be2f6ad439fbb7ee16d804ade1d4e23e" or
        hash.md5(0,filesize) == "73b09ba0ad914eaa46d4e06482690d00" or
        hash.md5(0,filesize) == "5be66c43f58b396ed5f0331f65a3e279" or
        hash.md5(0,filesize) == "28801a3e4bed8b5aeaf4d6ca49a70eea" or
        hash.md5(0,filesize) == "007256a7db8c565fc4fb47609acb7a11" or
        hash.md5(0,filesize) == "5e26f14f1bf986992937cae741c8d547" or
        hash.md5(0,filesize) == "4e29cb733c95c19d02e73893ac930341" or
        hash.md5(0,filesize) == "b5a15d784e05b49c87e4dec0e23fa36f" or
        hash.md5(0,filesize) == "50dfb9914dd479e61fd7a8e5ab46a1a2" or
        hash.md5(0,filesize) == "40e895ada11447d13efe17829a445086" or
        hash.md5(0,filesize) == "f622f601051efecfa04ab8e4801dc6e0" or
        hash.md5(0,filesize) == "48dcc4529aaedcc7e7786253053f3c7c" 
}