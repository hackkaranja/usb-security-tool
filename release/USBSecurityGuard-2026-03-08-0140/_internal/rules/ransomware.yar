rule Ransomware_Generic_FileEncryption_Behavior
{
    meta:
        description = "Detects generic ransomware behaviors: encryption API calls and ransom note strings"
        category     = "ransomware"
        severity     = "critical"

    strings:
        // Encryption API imports
        $api1 = "CryptEncrypt"        ascii wide
        $api2 = "CryptGenKey"         ascii wide
        $api3 = "CryptAcquireContext" ascii wide
        $api4 = "BCryptEncrypt"       ascii wide
        $api5 = "BCryptGenerateSymmetricKey" ascii wide

        // Ransom note keywords
        $note1 = "YOUR FILES HAVE BEEN ENCRYPTED" ascii wide nocase
        $note2 = "your files are encrypted"       ascii wide nocase
        $note3 = "All your files"                 ascii wide nocase
        $note4 = "pay the ransom"                 ascii wide nocase
        $note5 = "decrypt your files"             ascii wide nocase
        $note6 = "bitcoin"                        ascii wide nocase
        $note7 = "BTC wallet"                     ascii wide nocase
        $note8 = "HOW_TO_RESTORE"                 ascii wide nocase
        $note9 = "README_FOR_DECRYPT"             ascii wide nocase
        $note10 = "RECOVER_FILES"                 ascii wide nocase

        // File operations typical of ransomware
        $file1 = "DeleteShadowCopies"             ascii wide nocase
        $file2 = "vssadmin delete shadows"        ascii wide nocase
        $file3 = "bcdedit /set {default}"         ascii wide nocase
        $file4 = "wbadmin delete catalog"         ascii wide nocase

    condition:
        (2 of ($api*)) or
        (3 of ($note*)) or
        (1 of ($file*) and 1 of ($note*))
}

rule Ransomware_LockBit
{
    meta:
        description = "Detects LockBit ransomware indicators"
        category     = "ransomware"
        family       = "LockBit"
        severity     = "critical"

    strings:
        $s1 = "LockBit"              ascii wide nocase
        $s2 = "Restore-My-Files.txt" ascii wide nocase
        $s3 = ".lockbit"             ascii wide nocase
        $s4 = "lockbit_decryptor"    ascii wide nocase
        $s5 = "StopFirewall"         ascii wide
        $s6 = "DisableAntiSpyware"   ascii wide

        // Shadow copy deletion
        $del1 = "vssadmin.exe delete shadows /all /quiet" ascii wide nocase
        $del2 = "wmic shadowcopy delete"                  ascii wide nocase

    condition:
        2 of ($s*) or 1 of ($del*)
}

rule Ransomware_WannaCry
{
    meta:
        description = "Detects WannaCry / WannaCrypt ransomware"
        category     = "ransomware"
        family       = "WannaCry"
        severity     = "critical"

    strings:
        $s1 = "WannaDecryptor"    ascii wide
        $s2 = "WNCRY"             ascii wide
        $s3 = "WannaCrypt"        ascii wide
        $s4 = "@Please_Read_Me@"  ascii wide
        $s5 = "wcry@123"          ascii wide
        $s6 = "tasksche.exe"      ascii wide
        $s7 = "mssecsvc.exe"      ascii wide

        // EternalBlue / SMB exploit marker
        $smb1 = "\\\\\\\\127.0.0.1\\\\IPC$" ascii wide
        $smb2 = "SMBv1"                      ascii wide nocase

    condition:
        2 of ($s*) or ($smb1 and $smb2)
}

rule Ransomware_Office_Dropper
{
    meta:
        description = "Detects Office documents dropping or triggering ransomware"
        category     = "ransomware"
        filetype     = "office"
        severity     = "high"

    strings:
        // Macro indicators
        $macro1 = "AutoOpen"       ascii wide nocase
        $macro2 = "AutoExec"       ascii wide nocase
        $macro3 = "Document_Open"  ascii wide nocase

        // Payload delivery patterns
        $cmd1 = "powershell"   ascii wide nocase
        $cmd2 = "cmd.exe"      ascii wide nocase
        $cmd3 = "WScript.Shell" ascii wide nocase
        $cmd4 = "Shell("       ascii wide nocase
        $cmd5 = "CreateObject" ascii wide nocase

        // Ransomware note strings even inside docs
        $note1 = "encrypted"  ascii wide nocase
        $note2 = "ransom"     ascii wide nocase
        $note3 = "bitcoin"    ascii wide nocase

        // OLE magic bytes
        $ole = { D0 CF 11 E0 A1 B1 1A E1 }

    condition:
        $ole and
        (1 of ($macro*)) and
        (1 of ($cmd*)) and
        (1 of ($note*))
}

rule Ransomware_Script_Dropper
{
    meta:
        description = "Detects PS1/VBS/BAT/JS scripts used to deliver or execute ransomware"
        category     = "ransomware"
        filetype     = "script"
        severity     = "high"

    strings:
        $ps1  = "powershell" ascii wide nocase
        $enc1 = "-EncodedCommand" ascii wide nocase
        $enc2 = "-enc "          ascii wide nocase
        $dl1  = "DownloadString"  ascii wide nocase
        $dl2  = "DownloadFile"    ascii wide nocase
        $dl3  = "Invoke-Expression" ascii wide nocase
        $dl4  = "IEX("           ascii wide nocase
        $shad = "vssadmin"       ascii wide nocase
        $ext  = ".encrypted"     ascii wide nocase
        $note = "ransom"         ascii wide nocase

    condition:
        ($ps1 and 1 of ($enc*) and 1 of ($dl*)) or
        ($shad and ($ext or $note))
}