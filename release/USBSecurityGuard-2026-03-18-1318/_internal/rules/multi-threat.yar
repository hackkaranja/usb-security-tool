rule Suspicious_AntiAnalysis_Techniques
{
    meta:
        description = "Detects common anti-analysis and sandbox evasion techniques used across malware families"
        category     = "evasion"
        severity     = "medium"

    strings:
        $sandbox1 = "IsDebuggerPresent"   ascii wide
        $sandbox2 = "CheckRemoteDebuggerPresent" ascii wide
        $sandbox3 = "NtQueryInformationProcess"  ascii wide
        $sandbox4 = "GetTickCount"        ascii wide
        $sandbox5 = "QueryPerformanceCounter" ascii wide

        $vm1 = "VMware"       ascii wide nocase
        $vm2 = "VirtualBox"   ascii wide nocase
        $vm3 = "VBOX"         ascii wide nocase
        $vm4 = "Sandboxie"    ascii wide nocase
        $vm5 = "cuckoosandbox" ascii wide nocase

        $sleep1 = "Sleep(600000)"  ascii wide
        $sleep2 = "timeout /t"     ascii wide nocase

    condition:
        2 of ($sandbox*) or
        2 of ($vm*) or
        1 of ($sleep*)
}

rule Suspicious_UAC_Bypass
{
    meta:
        description = "Detects common UAC bypass techniques used by malware to escalate privileges"
        category     = "privilege_escalation"
        severity     = "high"

    strings:
        $s1 = "fodhelper.exe"   ascii wide nocase
        $s2 = "eventvwr.exe"    ascii wide nocase
        $s3 = "sdclt.exe"       ascii wide nocase
        $s4 = "ComputerDefaults.exe" ascii wide nocase
        $s5 = "DiskCleanup.exe" ascii wide nocase
        $s6 = "ConsentPromptBehaviorAdmin" ascii wide nocase
        $s7 = "CMSTPLUA"        ascii wide nocase
        $s8 = "bypassuac"       ascii wide nocase

    condition:
        2 of them
}