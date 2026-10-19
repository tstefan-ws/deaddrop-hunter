/*
    deaddrop-hunter - EtherHiding loader rules
    Scripts or binaries that resolve their C2/config from a smart contract by sending a
    read-only eth_call to a public blockchain RPC endpoint.

    License: MIT (see repository LICENSE)
*/

rule EtherHiding_Loader_RPC_EthCall
{
    meta:
        author = "deaddrop-hunter contributors"
        date = "2026-10-19"
        description = "Script/binary containing a public blockchain RPC hostname, an eth_call JSON-RPC request and a contract address or 4-byte selector (EtherHiding dead-drop resolver)"
        reference = "https://www.linkedin.com/pulse/hunting-etherhiding-from-one-cluster-ecosystem-alex-necula-r7l8e/"
        reference2 = "https://cloud.google.com/blog/topics/threat-intelligence/dprk-adopts-etherhiding"
        mitre_attack = "T1102.001"
        tlp = "TLP:CLEAR"
        score = 60

    strings:
        // Public JSON-RPC endpoints seen in EtherHiding loaders (Polygon, BSC, Ethereum)
        $rpc1  = "polygon-rpc.com" ascii wide nocase
        $rpc2  = "gateway.tenderly.co" ascii wide nocase
        $rpc3  = "publicnode.com" ascii wide nocase
        $rpc4  = "drpc.org" ascii wide nocase
        $rpc5  = "rpc.ankr.com" ascii wide nocase
        $rpc6  = "bsc-dataseed" ascii wide nocase
        $rpc7  = "data-seed-prebsc" ascii wide nocase
        $rpc8  = "bsc-testnet" ascii wide nocase
        $rpc9  = "infura.io" ascii wide nocase
        $rpc10 = "cloudflare-eth.com" ascii wide nocase
        $rpc11 = "llamarpc.com" ascii wide nocase
        $rpc12 = "quiknode.pro" ascii wide nocase
        $rpc13 = "1rpc.io" ascii wide nocase
        $rpc14 = "nodereal.io" ascii wide nocase
        $rpc15 = "g.alchemy.com" ascii wide nocase

        $m_call = "eth_call" ascii wide
        $m_json = "jsonrpc" ascii wide

        // "to":"0x<40 hex>" (contract) and "data":"0x<8 hex>..." (selector + args)
        $to   = /["']?to["']?\s*[:=]\s*["']0x[0-9a-fA-F]{40}["']/ ascii wide
        $data = /["']?data["']?\s*[:=]\s*["']0x[0-9a-fA-F]{8}/ ascii wide
        $addr = /0x[0-9a-fA-F]{40}[^0-9a-fA-F]/ ascii wide

    condition:
        filesize < 10MB
        and 1 of ($rpc*)
        and $m_call
        and ($to or $data or ($m_json and $addr))
}

rule EtherHiding_Loader_Web3_Library_Call
{
    meta:
        author = "deaddrop-hunter contributors"
        date = "2026-10-19"
        description = "Small script that builds a web3/ethers provider for a public RPC endpoint and calls a contract getter - typical injected ClearFake/EtherHiding loader pattern. Hunting rule: expect dApp false positives."
        reference = "https://cloud.google.com/blog/topics/threat-intelligence/unc5142-etherhiding-distribute-malware"
        mitre_attack = "T1102.001"
        tlp = "TLP:CLEAR"
        score = 40

    strings:
        $p1 = "new Web3(" ascii wide
        $p2 = "JsonRpcProvider(" ascii wide
        $p3 = "HttpProvider(" ascii wide
        $c1 = ".methods." ascii wide
        $c2 = ".call()" ascii wide
        $c3 = "eth.call(" ascii wide
        $h1 = "bsc-dataseed" ascii wide nocase
        $h2 = "data-seed-prebsc" ascii wide nocase
        $h3 = "polygon-rpc.com" ascii wide nocase
        $h4 = "bsc-testnet" ascii wide nocase
        $h5 = "publicnode.com" ascii wide nocase
        $h6 = "gateway.tenderly.co" ascii wide nocase
        $dec1 = "atob(" ascii wide
        $dec2 = "eval(" ascii wide
        $dec3 = "Function(" ascii wide

    condition:
        filesize < 2MB
        and 1 of ($p*)
        and 1 of ($c*)
        and 1 of ($h*)
        and 1 of ($dec*)
}
