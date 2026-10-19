/*
    deaddrop-hunter - stealth XMRig configuration rules

    The Polygon cluster found on 2026-10-19 (operator 0x19532c0fbaf0fb8c1d0f3fac0b704bf2f4645539)
    stores its XMRig configuration on-chain XOR-encoded with the single-byte key 0x5a.
    The plaintext starts with  {"algo":"rx/0"  which under key 0x5a becomes
        21 78 3B 36 3D 35 78 60 78 28 22 75 6A 78
    (computed and verified with Python: bytes(b ^ 0x5a for b in b'{"algo":"rx/0"')).
    On-chain this is usually seen hex-encoded as text: "21783b363d357860782822756a78".

    License: MIT (see repository LICENSE)
*/

rule XMRig_Stealth_Config_Plain
{
    meta:
        author = "deaddrop-hunter contributors"
        date = "2026-10-19"
        description = "Plaintext XMRig config using stealth/idle options that hide mining while monitoring tools (Taskmgr.exe, SystemInformer.exe) run"
        reference = "https://xmrig.com/docs/miner/config"
        mitre_attack = "T1496.001"
        tlp = "TLP:CLEAR"
        score = 70

    strings:
        $k_stealth = "\"stealth-targets\"" ascii wide
        $k_idlew   = "\"idle-wait\"" ascii wide
        $k_idlec   = "\"idle-cpu\"" ascii wide
        $k_nh      = "\"nicehash\"" ascii wide
        $k_algo    = "\"algo\"" ascii wide
        $k_pool    = "\"pools\"" ascii wide
        $t1 = "Taskmgr.exe" ascii wide nocase
        $t2 = "SystemInformer.exe" ascii wide nocase
        $t3 = "ProcessHacker.exe" ascii wide nocase
        $t4 = "procexp" ascii wide nocase
        $t5 = "perfmon.exe" ascii wide nocase

    condition:
        filesize < 20MB
        and $k_stealth
        and 1 of ($k_idle*)
        and ($k_nh or $k_algo or $k_pool or 1 of ($t*))
}

rule XMRig_Stealth_Config_XOR5A_OnChain
{
    meta:
        author = "deaddrop-hunter contributors"
        date = "2026-10-19"
        description = "XMRig config XOR-encoded with key 0x5a as stored in Polygon dead-drop contracts (stealth-XMRig cluster), binary or hex-text form"
        reference = "deaddrop-hunter docs/methodology.md - XOR key recovery; findings of 2026-10-19 (Polygon)"
        mitre_attack = "T1102.001, T1496.001, T1027"
        tlp = "TLP:CLEAR"
        score = 80

    strings:
        // {"algo":"rx/0"  XOR 0x5a
        $algo_bin     = { 21 78 3B 36 3D 35 78 60 78 28 22 75 6A 78 }
        // "stealth-targets"  XOR 0x5a
        $stealth_bin  = { 78 29 2E 3F 3B 36 2E 32 77 2E 3B 28 3D 3F 2E 29 78 }
        // "idle-wait"  XOR 0x5a
        $idle_bin     = { 78 33 3E 36 3F 77 2D 3B 33 2E 78 }
        // the same sequences hex-encoded as text (eth_call results, explorer dumps, data/*.json)
        $algo_hex     = "21783b363d357860782822756a78" ascii wide nocase
        $stealth_hex  = "78292e3f3b362e32772e3b283d3f2e2978" ascii wide nocase

    condition:
        any of them
}

rule XMRig_Stealth_Config_SingleByteXOR_Any
{
    meta:
        author = "deaddrop-hunter contributors"
        date = "2026-10-19"
        description = "XMRig stealth config hidden with any single-byte XOR key (covers key rotation away from 0x5a). Uses the YARA xor modifier."
        reference = "https://yara.readthedocs.io/en/stable/writingrules.html#xor-strings"
        mitre_attack = "T1027, T1496.001"
        tlp = "TLP:CLEAR"
        score = 60

    strings:
        $algo    = "{\"algo\":\"rx/0\"" xor(0x01-0xff)
        $stealth = "\"stealth-targets\"" xor(0x01-0xff)
        $idle    = "\"idle-wait\"" xor(0x01-0xff)

    condition:
        filesize < 20MB and ($algo or ($stealth and $idle))
}
