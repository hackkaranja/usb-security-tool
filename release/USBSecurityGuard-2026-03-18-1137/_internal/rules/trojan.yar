rule Trojan_Generic_Backdoor_Behavior
{
    meta:
        description = "Detects generic remote access trojan / backdoor behaviors"
        category     = "trojan"
        severity     = "high"

    strings:
        // RAT / C2 connectivity patterns
        $c2_1 = "reverse shell"   ascii wide nocase
        $c2_2 = "bind shell"      ascii wide nocase
        $c2_3 = "cmd.exe /c"      ascii wide nocase
        $c2_4 = "/bin/bash -i"    ascii wide nocase
        $c2_5 = "nc -e"           ascii wide nocase
        $c2_6 = "ncat"            ascii wide nocase

        // Socket / network APIs
        $net1 = "WSAStartup"  ascii wide
        $net2 = "connect("    ascii wide
        $net3 = "recv("       ascii wide
        $net4 = "send("       ascii wide

        // Persistence mechanisms
        $pers1 = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii wide nocase
        $pers2 = "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii wide nocase
        $pers3 = "schtasks /create" ascii wide nocase
        $pers4 = "New-ScheduledTask" ascii wide nocase

        // Process injection
        $inj1 = "VirtualAllocEx"    ascii wide
        $inj2 = "WriteProcessMemory" ascii wide
        $inj3 = "CreateRemoteThread" ascii wide

    condition:
        (2 of ($c2*)) or
        (2 of ($net*) and 1 of ($pers*)) or
        (2 of ($inj*))
}

rule Trojan_RAT_Mimikatz_Creds
{
    meta:
        description = "Detects Mimikatz credential harvesting tool or similar"
        category     = "trojan"
        family       = "Mimikatz"
        severity     = "critical"

    strings:
        $s1 = "mimikatz"          ascii wide nocase
        $s2 = "sekurlsa"          ascii wide nocase
        $s3 = "lsadump"           ascii wide nocase
        $s4 = "privilege::debug"  ascii wide nocase
        $s5 = "sekurlsa::logonPasswords" ascii wide nocase
        $s6 = "kerberos::list"    ascii wide nocase
        $s7 = "pass-the-hash"     ascii wide nocase
        $s8 = "Benjamin DELPY"    ascii wide

    condition:
        2 of them
}

rule Trojan_PowerShell_Backdoor
{
    meta:
        description = "Detects PowerShell-based backdoor or RAT patterns"
        category     = "trojan"
        filetype     = "script"
        severity     = "high"

    strings:
        $ps1 = "powershell" ascii wide nocase

        // Obfuscation techniques
        $ob1 = "-EncodedCommand"  ascii wide nocase
        $ob2 = "-WindowStyle Hidden" ascii wide nocase
        $ob3 = "-NonInteractive"  ascii wide nocase
        $ob4 = "FromBase64String" ascii wide nocase
        $ob5 = "[System.Convert]::FromBase64String" ascii wide nocase

        // Network / download cradles
        $dl1 = "Net.WebClient"       ascii wide nocase
        $dl2 = "DownloadString"      ascii wide nocase
        $dl3 = "Invoke-Expression"   ascii wide nocase
        $dl4 = "IEX("                ascii wide nocase
        $dl5 = "Start-BitsTransfer"  ascii wide nocase

        // Reverse shell
        $rev1 = "System.Net.Sockets.TCPClient" ascii wide
        $rev2 = "NetworkStream"                ascii wide
        $rev3 = "StreamReader"                 ascii wide
        $rev4 = "StreamWriter"                 ascii wide

    condition:
        $ps1 and (
            (2 of ($ob*) and 1 of ($dl*)) or
            (3 of ($rev*))
        )
}

rule Trojan_VBS_Backdoor
{
    meta:
        description = "Detects VBScript-based backdoor behaviors"
        category     = "trojan"
        filetype     = "script"
        severity     = "high"

    strings:
        $obj1 = "CreateObject(\"WScript.Shell\")"       ascii nocase
        $obj2 = "CreateObject(\"Scripting.FileSystemObject\")" ascii nocase
        $obj3 = "CreateObject(\"MSXML2.XMLHTTP\")"      ascii nocase
        $obj4 = "CreateObject(\"ADODB.Stream\")"        ascii nocase

        $exec1 = ".Run("    ascii nocase
        $exec2 = ".Exec("   ascii nocase
        $exec3 = "Shell("   ascii nocase

        $dl1 = ".Open \"GET\"" ascii nocase
        $dl2 = ".Send"         ascii nocase
        $dl3 = ".responseBody" ascii nocase

        $hide1 = "vbHide"      ascii nocase
        $hide2 = "WindowStyle" ascii nocase

    condition:
        (2 of ($obj*) and 1 of ($exec*)) or
        (1 of ($obj*) and 2 of ($dl*)) or
        (1 of ($exec*) and 1 of ($hide*) and 1 of ($dl*))
}

rule Trojan_Office_Macro_Dropper
{
    meta:
        description = "Detects Office documents with suspicious macro-based dropper behavior"
        category     = "trojan"
        filetype     = "office"
        severity     = "high"

    strings:
        $ole = { D0 CF 11 E0 A1 B1 1A E1 }

        $macro1 = "AutoOpen"       ascii nocase
        $macro2 = "Document_Open"  ascii nocase
        $macro3 = "Workbook_Open"  ascii nocase

        $shell1 = "Shell("         ascii nocase
        $shell2 = "WScript.Shell"  ascii nocase
        $shell3 = "CreateObject"   ascii nocase

        $payload1 = "powershell"   ascii nocase
        $payload2 = "cmd /c"       ascii nocase
        $payload3 = "mshta"        ascii nocase
        $payload4 = "regsvr32"     ascii nocase
        $payload5 = "rundll32"     ascii nocase
        $payload6 = "certutil"     ascii nocase

    condition:
        $ole and
        (1 of ($macro*)) and
        (1 of ($shell*)) and
        (1 of ($payload*))
}