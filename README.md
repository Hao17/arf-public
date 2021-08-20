## Rootkit专杀框架

运行环境为Win7 SP1 x64到Win10 21H1 x64

Rootkit专杀框架会提供以下功能，以下检测项均使用Yara规则进行匹配：

（1）多个系统回调检测及移除

（2）r0及r3进程、线程检测及处置

（3）解除基于minifilter的文件保护并处置

（4）注册表驱动及服务项的检测及处置

利用配置文件，可以快速对新型rootkit提取规则并作出处置。

## 检测流程

针对常见的rootkit病毒，遵循以下处理流程

* 线程扫描，结束线程
* 进程扫描，结束进程
* 回调扫描
  * 注册表回调
  * 关机回调
  * 进程回调
  * 线程回调
  * 映像载入回调
* 注册表扫描，删除对应注册表项
* 文件扫描，删除残留的恶意文件

## 版本

### v0.2.3

功能更新
1）重构注册表模块
2）注册表已支持Yara规则匹配


### v0.2.2

1）重写了进程与线程模块
2）添加了对线程的查杀与处置

### v0.2.1

1）添加了关机回调的检测和移除（Shutdown以及LastChanceShutdown）
2）添加了驱动检查和卸载功能
3）修正了数个导致的蓝屏的BUG
4）添加了麻辣香锅变种b样本规则

### v0.2

1）回调检测及移除功能合入版本，目前已支持进程创建、线程创建、映像加载、注册表回调检测
2）更换了注册表检测方案，目前为检测并删除驱动、服务映像文件为恶意的注册表项
3）结束进程模块移至驱动，并提高了r3进程权限，防止无法访问进程内存及结束进程问题
4）已添加“麻辣香锅”回调特征，并修复win10下处置失败的BUG
5）已添加“紫狐”回调特征

### v0.1

基础功能的开发

## 麻辣香锅-a

下面将以“麻辣香锅”这个rootkit作为样例，展示整个处置流程

麻辣香锅处置困难的原因：

（1）创建了三个恶意进程“Windows Mobile User Experience”、“DvUpdate”、“DumpUp”，均为SYSTEM权限，使用Process Hacker等工具无法结束

（2）创建并利用minifilter隐藏了驱动及进程文件

（3）创建了注册表项并利用注册表回调保护自身，无法删除

（4）创建了线程回调、注册表回调、关机回调等多个回调

因此，创建如下麻辣香锅的Yara匹配规则

**进程**

取进程IMAGE段内存DUMP文件作为特征

```c++
rule DumpUp_mem {
   strings:
      $x1 = "C:\\Users\\dev\\AppData\\local\\Mlxg_km\\DumpUp.exe" fullword ascii
      $x2 = "http://du.testjj.com:8084/post_dump" fullword ascii
	...
      $s20 = "Content-Type: %s%s%s" fullword ascii
   condition:
      all of them
}

rule Windows_Mobile_User_Experience { ... }
rule DvUpdate { ... }
```

**文件**

取文件hash作为特征

```
import "hash"

rule mlxg 
{
    condition:
        hash.md5(0,filesize) == "253B027556BA7048261B09DCB7ED1C7F" or
        hash.md5(0,filesize) == "062ACDAC0BED29B0049D48263BD7B169" or
        hash.md5(0,filesize) == "E6E2590BA5978B8297A6E630F424E7BC" or
        hash.md5(0,filesize) == "0A98900CF6D9546B1789A0D822B3C7C8" or
        hash.md5(0,filesize) == "C21DF591EEFD4EC978FD3488C6D1C673" or
        hash.md5(0,filesize) == "7D0E90CE1A84C92DE9E8731AE3C567FC" or
        hash.md5(0,filesize) == "E8C4FD6E0F1A169D323CA3735F3488A9"
}
```

**回调**

在rules/callback目录下创建mlxg.yar文件，并在callback.yar内添加

```
.include "./rules/callback/mlxg.yar"
```

相关回调最好取反汇编内的E8、E9、74、75 {offset}也就是相对跳转指令汇编，比较精确且不容易误报

建议使用PCHunter提取，或者利用windbg手动提取（注意：PCHunter对LoadImage检测有问题）

![image-20210709143306802](C:\Users\Syec\OneDrive\assets\image-20210709143306802.png)

回调规则如下:

```c
//线程创建回调
rule thread_callback {
    strings:
        $s1 = {74 07}
        $s2 = {E8 28 E8 FF FF}
    condition:
        all of them
}

//映像加载回调
rule image_callback {
    strings:
        $s1 = {74 07}
        $s2 = {E8 28 E8 FF FF}
    condition:
        all of them
}

//注册表回调
rule registry_callback {
    strings:
        $s1 = {FF 15 30 22 00 00}
        $s2 = {0F 84 88 00 00 00}
        $s3 = {76 05}
        $s4 = {75 69}
    condition:
        all of them
}

//关机回调A
rule shutdown_callback1 {
    strings:
        $s1 = {E8 AC 40 00 00}
        $s2 = {E8 98 40 00 00}
        $s3 = {FF 15 41 5B 00 00}
        $s4 = {FF 15 28 5B 00 00}
    condition:
        all of them
}

//关机回调B
rule shutdown_callback2 {
    strings:
        $s1 = {E8 0B 07 00 00}
        $s2 = {E9 D2 01 00 00}
    condition:
        all of them
}
```

**注册表项**

扫描驱动、服务对应的ImagePath，转而进行文件yara匹配删除

![image-20210713162211868](C:\Users\Syec\OneDrive\assets\image-20210713162211868.png)

## 麻辣香锅-b

**回调**

```yara
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
```

**文件**

```
import "hash"

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
```

## 紫狐

**系统回调**

![image-20210701111354901](C:\Users\Syec\OneDrive\assets\image-20210701111354901.png)

隐藏注册表扫描方案已弃用，因为紫狐注册表回调匹配规则有问题，会隐藏一大批注册项

![image-20210701111059102](C:\Users\Syec\OneDrive\assets\image-20210701111059102.png)

卡巴斯基TdssKiller同样会误报

![image-20210722150506321](C:\Users\Syec\OneDrive\assets\image-20210722150506321.png)



**注册表**

```
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
```



## Sality.bh

Sality样本仅作线程注入清理样例，不提供sality感染文件修复等功能

**进程注入**

在被注入的进程中，逐个看线程堆栈找到了异常线程的起始点

![image-20210729194143358](C:\Users\Syec\OneDrive\assets\image-20210729194143358.png)

可以线程开始地址指向的是一个可执行程序，内存类型没有做伪装，就是Private

![image-20210729193958478](C:\Users\Syec\OneDrive\assets\image-20210729193958478.png)

这里取前0x100字节hash做特征码

```c
import "hash"

rule sality_bh
{
    meta:
        description = "sality_bh"
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
```

清理结果

![image-20210809162405354](C:\Users\Syec\OneDrive\assets\image-20210809162405354.png)

