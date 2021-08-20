/*
   YARA Rule Set
   Author: yarGen Rule Generator
   Date: 2021-06-30
   Identifier: 
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule Windows_Mobile_User_Experience_Server {
   meta:
      description = " - file Windows Mobile User Experience Server.exe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-06-30"
      hash1 = "72a6ef4417e65f10afba8782f6d9202f3a3fc16a278b6403ba2739047b073cac"
   strings:
      $x1 = "DumpUp.exe" fullword wide
      $s2 = "api-ms-win-core-synch-l1-2-0.dll" fullword wide /* reversed goodware string 'lld.0-2-1l-hcnys-eroc-niw-sm-ipa' */
      $s3 = "D:\\Work\\Install_Driver\\Driver_helper\\Debug\\Windows Mobile User Experience Server.pdb" fullword ascii
      $s4 = "C:\\Users\\" fullword wide
      $s5 = "  </trustInfo><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security><requestedPrivileges><requestedExecutionLevel leve" ascii
      $s6 = "\"requireAdministrator\" uiAccess=\"false\"></requestedExecutionLevel></requestedPrivileges></security></trustInfo><compatibilit" ascii
      $s7 = "DvUpdate.exe" fullword wide
      $s8 = "zhudongfangyu.exe" fullword wide
      $s9 = "QQPCRTP.exe" fullword wide
      $s10 = "wsctrl.exe" fullword wide
      $s11 = "regsvr32.exe /u " fullword wide
      $s12 = "regsvr32.exe /s /u " fullword wide
      $s13 = "Windows.exe" fullword wide
      $s14 = "  </trustInfo><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security><requestedPrivileges><requestedExecutionLevel leve" ascii
      $s15 = "d:\\agent\\_work\\3\\s\\src\\vctools\\crt\\vcruntime\\src\\eh\\std_type_info.cpp" fullword ascii
      $s16 = "d:\\agent\\_work\\3\\s\\src\\vctools\\crt\\crtw32\\misc\\stlcomparestringa.cpp" fullword wide
      $s17 = "d:\\agent\\_work\\3\\s\\src\\vctools\\crt\\vcruntime\\src\\internal\\per_thread_data.cpp" fullword ascii
      $s18 = "C:\\Documents and Settings\\" fullword wide
      $s19 = "d:\\agent\\_work\\3\\s\\src\\vctools\\crt\\vcstartup\\src\\misc\\thread_safe_statics.cpp" fullword wide
      $s20 = "d:\\agent\\_work\\3\\s\\src\\vctools\\crt\\vcruntime\\src\\eh\\std_exception.cpp" fullword wide
   condition:
      all of them
}

rule DvUpdate_mem {
   meta:
      description = " - file DvUpdate_mem.exe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-07-13"
      hash1 = "f39e8a6633bf2d8aecd1c2dbea00c5682d7d26ba1dc7b9af5575a07f49c1212a"
   strings:
      $x1 = "C:\\Users\\dev\\AppData\\local\\Mlxg_km\\DvUpdate.exe" fullword ascii
      $s2 = "api-ms-win-core-synch-l1-2-0.dll" fullword wide /* reversed goodware string 'lld.0-2-1l-hcnys-eroc-niw-sm-ipa' */
      $s3 = "SEC_E_ILLEGAL_MESSAGE (0x%08X) - This error usually occurs when a fatal SSL/TLS alert is received (e.g. handshake failed). More " ascii
      $s4 = "Failed reading the chunked-encoded stream" fullword ascii
      $s5 = "D:\\Work\\Install_Driver\\Driver_helper\\Release\\DvUpdate.pdb" fullword ascii
      $s6 = "Negotiate: noauthpersist -> %d, header part: %s" fullword ascii
      $s7 = "AppPolicyGetProcessTerminationMethod" fullword ascii
      $s8 = "failed to load WS2_32.DLL (%u)" fullword ascii
      $s9 = "schannel: CertGetNameString() failed to match connection hostname (%s) against server certificate names" fullword ascii
      $s10 = "du.testjj.com" fullword ascii
      $s11 = "No more connections allowed to host %s: %zu" fullword ascii
      $s12 = " gethostbyname error for host:" fullword ascii
      $s13 = "RESOLVE %s:%d is - old addresses discarded!" fullword ascii
      $s14 = "Content-Type: %s%s%s" fullword ascii
      $s15 = "Content-Disposition: %s%s%s%s%s%s%s" fullword ascii
      $s16 = "Excess found in a read: excess = %zu, size = %I64d, maxdownload = %I64d, bytecount = %I64d" fullword ascii
      $s17 = "SOCKS4%s: connecting to HTTP proxy %s port %d" fullword ascii
      $s18 = "SEC_E_ILLEGAL_MESSAGE (0x%08X) - This error usually occurs when a fatal SSL/TLS alert is received (e.g. handshake failed). More " ascii
      $s19 = "No valid port number in connect to host string (%s)" fullword ascii
      $s20 = "Excessive password length for proxy auth" fullword ascii
   condition:
      all of them
}

rule DumpUp_mem {
   meta:
      description = " - file DumpUp_MemDump"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-07-13"
      hash1 = "ba55bbec38f7d1b3876d0adefebf4e02defaeb4f77319b0cca23c68243b1cb49"
   strings:
      $x1 = "C:\\Users\\dev\\AppData\\local\\Mlxg_km\\DumpUp.exe" fullword ascii
      $x2 = "http://du.testjj.com:8084/post_dump" fullword ascii
      $x3 = "6\\ zip 1.01 Copyright 1998-2004 Gilles Vollant - http://www.winimage.com/zLibDll" fullword ascii
      $x4 = "D:\\Work\\Install_Driver\\Driver_helper\\Release\\DumpUp.pdb" fullword ascii
      $x5 = "DumpUp.exe" fullword wide
      $s6 = "api-ms-win-core-synch-l1-2-0.dll" fullword wide /* reversed goodware string 'lld.0-2-1l-hcnys-eroc-niw-sm-ipa' */
      $s7 = "SEC_E_ILLEGAL_MESSAGE (0x%08X) - This error usually occurs when a fatal SSL/TLS alert is received (e.g. handshake failed). More " ascii
      $s8 = "Failed reading the chunked-encoded stream" fullword ascii
      $s9 = "dumping" fullword wide
      $s10 = "Negotiate: noauthpersist -> %d, header part: %s" fullword ascii
      $s11 = "AppPolicyGetProcessTerminationMethod" fullword ascii
      $s12 = "failed to load WS2_32.DLL (%u)" fullword ascii
      $s13 = "kmdf_protect.sys" fullword ascii
      $s14 = "kmdf_look.sys" fullword ascii
      $s15 = "schannel: CertGetNameString() failed to match connection hostname (%s) against server certificate names" fullword ascii
      $s16 = "No more connections allowed to host %s: %zu" fullword ascii
      $s17 = "RESOLVE %s:%d is - old addresses discarded!" fullword ascii
      $s18 = "Content-Disposition: %s%s%s%s%s%s%s" fullword ascii
      $s19 = "Excess found in a read: excess = %zu, size = %I64d, maxdownload = %I64d, bytecount = %I64d" fullword ascii
      $s20 = "Content-Type: %s%s%s" fullword ascii
   condition:
      all of them
}

