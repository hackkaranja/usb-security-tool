rule CryptoMiner_Generic
{
    meta:
        description = "Detects generic cryptocurrency miner indicators"
        category     = "cryptominer"
        severity     = "medium"

    strings:
        // Mining pool / protocol keywords
        $pool1 = "stratum+tcp://"   ascii wide nocase
        $pool2 = "stratum+ssl://"   ascii wide nocase
        $pool3 = "mining.pool"      ascii wide nocase
        $pool4 = "pool.minexmr"     ascii wide nocase
        $pool5 = "xmrpool"          ascii wide nocase
        $pool6 = "nanopool"         ascii wide nocase
        $pool7 = "f2pool"           ascii wide nocase

        // Common miner strings
        $miner1 = "xmrig"           ascii wide nocase
        $miner2 = "cryptonight"     ascii wide nocase
        $miner3 = "randomx"         ascii wide nocase
        $miner4 = "nicehash"        ascii wide nocase
        $miner5 = "monero"          ascii wide nocase
        $miner6 = "--donate-level"  ascii wide nocase
        $miner7 = "--coin"          ascii wide nocase
        $miner8 = "--threads"       ascii wide nocase

        // Wallet address patterns (XMR/ETH)
        $wallet1 = /4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}/ // Monero address
        $wallet2 = /0x[0-9a-fA-F]{40}/                 // Ethereum address

    condition:
        1 of ($pool*) or
        2 of ($miner*) or
        1 of ($wallet*)
}

rule CryptoMiner_XMRig
{
    meta:
        description = "Detects XMRig Monero miner binary or config"
        category     = "cryptominer"
        family       = "XMRig"
        severity     = "high"

    strings:
        $s1 = "xmrig"                ascii wide nocase
        $s2 = "XMRig"                ascii wide
        $s3 = "RandomX"              ascii wide
        $s4 = "--donate-level"       ascii wide
        $s5 = "cryptonight"          ascii wide nocase
        $s6 = "\"algo\""             ascii wide
        $s7 = "\"pools\""            ascii wide
        $s8 = "\"pass\""             ascii wide
        $s9 = "stratum"              ascii wide nocase

    condition:
        3 of them
}

rule CryptoMiner_Script_Dropper
{
    meta:
        description = "Detects scripts that download and execute crypto miners"
        category     = "cryptominer"
        filetype     = "script"
        severity     = "high"

    strings:
        $dl1 = "DownloadFile"       ascii wide nocase
        $dl2 = "DownloadString"     ascii wide nocase
        $dl3 = "wget "              ascii wide nocase
        $dl4 = "curl "              ascii wide nocase
        $dl5 = "Invoke-WebRequest"  ascii wide nocase
        $dl6 = "Net.WebClient"      ascii wide nocase

        $miner1 = "xmrig"           ascii wide nocase
        $miner2 = "stratum"         ascii wide nocase
        $miner3 = "cryptonight"     ascii wide nocase
        $miner4 = "monero"          ascii wide nocase
        $miner5 = "nicehash"        ascii wide nocase

        $exec1 = "Start-Process"    ascii wide nocase
        $exec2 = "Invoke-Expression" ascii wide nocase
        $exec3 = ".Run("            ascii wide nocase
        $exec4 = "Shell("           ascii wide nocase

    condition:
        (1 of ($dl*)) and
        (1 of ($miner*)) and
        (1 of ($exec*))
}

rule CryptoMiner_Office_Dropper
{
    meta:
        description = "Detects Office documents dropping crypto mining malware via macros"
        category     = "cryptominer"
        filetype     = "office"
        severity     = "high"

    strings:
        $ole = { D0 CF 11 E0 A1 B1 1A E1 }

        $macro1 = "AutoOpen"       ascii nocase
        $macro2 = "Document_Open"  ascii nocase
        $macro3 = "Workbook_Open"  ascii nocase

        $cmd1 = "powershell"       ascii nocase
        $cmd2 = "cmd /c"           ascii nocase
        $cmd3 = "WScript.Shell"    ascii nocase

        $miner1 = "xmrig"          ascii nocase
        $miner2 = "stratum"        ascii nocase
        $miner3 = "monero"         ascii nocase
        $miner4 = "cryptonight"    ascii nocase
        $miner5 = "nicehash"       ascii nocase

    condition:
        $ole and
        (1 of ($macro*)) and
        (1 of ($cmd*)) and
        (1 of ($miner*))
}