/*
   YARA Rule Set
   Author: yarGen Rule Generator
   Date: 2021-06-30
   Identifier: 
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule Ms9CC91F52App {
   meta:
      description = " - file Ms9CC91F52App.dll"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-06-30"
      hash1 = "4f89fbfb03df6afbebe243c20e0d359e76874e035199ce3ab35bbf7c6f8ad808"
   strings:
      $s1 = "SetupAs64.dll" fullword ascii
      $s2 = "xn~JveyeS3d" fullword ascii
      $s3 = "This program must be run under Win64" fullword ascii
      $s4 = "Uqknrdu" fullword ascii
      $s5 = "mMqkdf2" fullword ascii
      $s6 = "MpvTrd5" fullword ascii
      $s7 = "wkfldo" fullword ascii
      $s8 = "UWbLYLj7" fullword ascii
      $s9 = "ServiceMain" fullword ascii /* Goodware String - occured 486 times */
      $s10 = "!YGAmFeTRo" fullword ascii
      $s11 = "_CEhGi=y" fullword ascii
      $s12 = "dpoLOC$\"" fullword ascii
      $s13 = "hzdCX?" fullword ascii
      $s14 = "EdgO3l+" fullword ascii
      $s15 = "RXfN.~ZQhG" fullword ascii
      $s16 = "Sa?wKEL+eRX" fullword ascii
      $s17 = "tdQf(v9<" fullword ascii
      $s18 = ".zUWoD0s" fullword ascii
      $s19 = "!MgRd%`-" fullword ascii
      $s20 = "LQdUhYH&" fullword ascii
   condition:
      all of them
}