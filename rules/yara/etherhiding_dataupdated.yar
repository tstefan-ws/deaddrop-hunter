/*
    deaddrop-hunter - DataUpdated(string,string) fingerprint
    topic0 = keccak256("DataUpdated(string,string)")
           = 0xee986145c636aca5c6c0b4ce0e9d371e77ab30b3e28fe5c3a8d977f05fc8cf24
    (verified 2026-10-19). Matches tooling, ABIs, loaders or memory dumps that reference
    the event used by the contracts tracked in config/hunts.toml.

    License: MIT (see repository LICENSE)
*/

rule EtherHiding_DataUpdated_Event_Fingerprint
{
    meta:
        author = "deaddrop-hunter contributors"
        date = "2026-10-19"
        description = "References the DataUpdated(string,string) event signature or its keccak256 topic hash, used by on-chain config/C2 dead-drop contracts"
        reference = "https://www.linkedin.com/pulse/hunting-etherhiding-from-one-cluster-ecosystem-alex-necula-r7l8e/"
        mitre_attack = "T1102.001"
        tlp = "TLP:CLEAR"
        score = 50

    strings:
        $sig       = "DataUpdated(string,string)" ascii wide
        $topic_hex = "ee986145c636aca5c6c0b4ce0e9d371e77ab30b3e28fe5c3a8d977f05fc8cf24" ascii wide nocase
        // the same 32 bytes in binary form (e.g. PUSH32 in contract bytecode, packed buffers)
        $topic_raw = { EE 98 61 45 C6 36 AC A5 C6 C0 B4 CE 0E 9D 37 1E 77 AB 30 B3 E2 8F E5 C3 A8 D9 77 F0 5F C8 CF 24 }

    condition:
        any of them
}

rule EtherHiding_Known_Update_Selectors_With_RPC
{
    meta:
        author = "deaddrop-hunter contributors"
        date = "2026-10-19"
        description = "Script referencing a known dead-drop contract update selector (0x68446ead stealth-XMRig config, 0xcef6d209 C2 URL rotation) together with JSON-RPC usage - likely operator tooling"
        reference = "deaddrop-hunter config/hunts.toml - findings of 2026-10-19 (Polygon)"
        mitre_attack = "T1102.001"
        tlp = "TLP:CLEAR"
        score = 70

    strings:
        $sel1 = "68446ead" ascii wide nocase
        $sel2 = "cef6d209" ascii wide nocase
        $rpc1 = "eth_sendRawTransaction" ascii wide
        $rpc2 = "eth_call" ascii wide
        $rpc3 = "jsonrpc" ascii wide
        $rpc4 = "signTransaction" ascii wide

    condition:
        filesize < 10MB and 1 of ($sel*) and 1 of ($rpc*)
}
