# Sigma rules

Host-side detections for blockchain dead-drop ("EtherHiding") malware and the delivery chains
that use it. All rules validate with `sigma check rules/sigma` (pySigma 1.5, ATT&CK v20 tags) and
are tagged `status: experimental`.

| File | Logsource | What it catches | Level |
|---|---|---|---|
| `windows/dns_query_win_nonbrowser_blockchain_rpc.yml` | windows / dns_query | Script engine, LOLBin or downloader resolving a public blockchain RPC host | medium |
| `windows/net_connection_win_nonbrowser_blockchain_rpc.yml` | windows / network_connection | Same, as an outbound connection (needs `DestinationHostname`) | medium |
| `macos/net_connection_macos_nonbrowser_blockchain_rpc.yml` | macos / network_connection | osascript, curl, shells, python/node connecting to an RPC host | medium |
| `macos/file_event_macos_launchagent_plist_by_script.yml` | macos / file_event | `.plist` dropped in `~/Library/LaunchAgents` by osascript/bash/curl/... | medium |
| `macos/proc_creation_macos_tccutil_reset_all.yml` | macos / process_creation | `tccutil reset All` (or reset of a sensitive TCC service) | high |
| `windows/registry_set_win_clickfix_runmru_download_cradle.yml` | windows / registry_set | ClickFix: RunMRU entry with powershell/mshta/curl/cmd and a URL | high |
| `proc_creation_eth_call_jsonrpc_cmdline.yml` | process_creation (any OS) | Command line carrying an inline `eth_call` JSON-RPC body | high |

Convert with [sigma-cli](https://github.com/SigmaHQ/sigma-cli), for example:

```bash
pip install sigma-cli
sigma plugin install splunk         # or: elasticsearch, microsoft365defender, ...
sigma convert -t splunk -p sysmon rules/sigma/windows/
```

## Tuning

The RPC-host rules are deliberately broad: **public RPC endpoints are legitimate
infrastructure.** The signal is *who* talks to them, not *that* someone does. Before deploying
them as alerts, baseline for a week and tune:

- **Browsers and wallets are already out of scope** because the rules only match an explicit
  list of script engines and downloaders. If your EDR reports DNS from a broker process (e.g.
  `svchost.exe` for the DNS client), use the network-connection variants instead.
- **Developers and CI**: blockchain developers run `node`, `python`, `curl` against these
  endpoints all day. Exclude by host group, user, or parent process (IDEs, `npm`, `hardhat`,
  `foundry`/`anvil`, `truffle`, `brownie`, `pytest`), e.g. add
  `filter_optional_dev: ParentImage|endswith: ['\Code.exe', '\idea64.exe']`.
- **dApps and trading bots** running as services: exclude by signed path or service account.
- **Monitoring tools** (including deaddrop-hunter itself) will match; exclude their host.
- **Endpoint list drift**: providers add hostnames frequently. Keep the list in sync with
  [`docs/providers.md`](../../docs/providers.md) and the `[chains.*]` RPCs in
  `config/hunts.toml`. Prefer suffix wildcards (`*.publicnode.com`) over exact names.
- **Raise severity** when the same host also shows: a ClickFix RunMRU entry, a fresh
  LaunchAgent, `tccutil reset`, or a child `powershell -enc`/`mshta` shortly after the RPC call.
  Correlating the RPC rule with any of the high rules is a strong EtherHiding indicator.

Rule-specific notes:

- **eth_call command line**: very low volume in most enterprises. Developer laptops are the
  main false-positive source. If you see it from `mshta.exe` or a `wscript` child, escalate.
- **RunMRU / ClickFix**: values end in `\1`; the rule ignores the `MRUList` index value. Help
  desks that ask users to paste commands into Win+R will trigger it; ask them to stop.
- **LaunchAgent plist**: Homebrew (`brew services`), dotfile managers and MDM shell scripts
  create LaunchAgents via shell. Allow-list by plist name or parent (Jamf, Munki, Kandji).
- **tccutil**: legitimate use normally targets a bundle id (`tccutil reset Camera com.vendor.app`);
  a bare `reset All` on a user endpoint is rare.

## ATT&CK

Tags follow ATT&CK v20 as shipped with current pySigma (tactics `stealth` and
`defense-impairment` replace the former `defense-evasion`; `T1685` replaces `T1562.001`).
If your SIEM still maps ATT&CK v17 or earlier, the equivalents are `defense-evasion` and
`T1562.001`.
