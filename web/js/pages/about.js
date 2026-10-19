import { h, extLink } from '../dom.js';
import { REPO_URL, ISSUES_URL } from '../fmt.js';
import { pageHead } from '../ui.js';

export function renderAbout() {
  return h('div', { class: 'prose' },
    pageHead({ title: 'About & methodology', sub: 'How deaddrop-hunter finds malware configuration hidden on public blockchains.' }),
    h('h2', null, 'The technique'),
    h('p', null, '"EtherHiding" malware does not hard-code its command-and-control server or miner configuration. Instead it reads it from a public blockchain: the loader performs a read-only ', h('code', null, 'eth_call'), ' to a smart contract (or reads transaction data / memos on non-EVM chains) and decodes the returned string. The operator rotates infrastructure by sending a transaction that overwrites the stored value. No takedown can remove the data, and the read leaves no trace on-chain.'),
    h('p', null, 'The same transparency works against the operators: every rotation is a public transaction, signed by a wallet, with the old and new value recoverable.'),
    h('h2', null, 'How we hunt'),
    h('ol', null,
      h('li', null, h('strong', null, 'Sweep fingerprints. '), 'Search event logs by topic0 (e.g. ', h('code', null, 'DataUpdated(string,string)'), '), transactions by 4-byte function selector, and every transaction sent by known operator wallets.'),
      h('li', null, h('strong', null, 'Decode. '), 'Try plain text, single-byte XOR, base64 and hex; record which decoder produced a meaningful value.'),
      h('li', null, h('strong', null, 'Extract & classify. '), 'Pull out IPs, domains, URLs, ports and payout wallets; tag families with classification rules.'),
      h('li', null, h('strong', null, 'Pivot. '), 'From a contract to its operator wallets, from wallets to their other contracts and funders, and group everything sharing an operator into a cluster.'),
      h('li', null, h('strong', null, 'Track. '), 'Re-run incrementally from the last scanned block; every rotation is kept so the timeline shows exactly what changed and when.')),
    h('p', null, 'The hunter only uses read-only RPC methods (', h('code', null, 'eth_getLogs'), ', ', h('code', null, 'eth_call'), ', transaction and block lookups). It never signs or sends transactions.'),
    h('h2', null, 'Safety'),
    h('div', { class: 'callout' },
      h('p', null, h('strong', null, 'Never visit the indicators. '), 'Values shown here come from attacker-controlled contracts. They are displayed defanged (', h('code', null, 'hxxp://'), ', ', h('code', null, '78[.]40[.]198[.]61'), ') and are never rendered as links. Only block-explorer links built from validated addresses and transaction hashes are clickable.'),
      h('p', null, 'Data is ', h('strong', null, 'TLP:CLEAR'), ' and provided as-is. Automated classification may produce false positives: verify before blocking or attributing.')),
    h('h2', null, 'This dashboard'),
    h('p', null, 'A static site: no backend, no tracking, no third-party scripts. Your watchlist, theme and chain filter live only in this browser\'s local storage.'),
    h('h2', null, 'Contribute & report'),
    h('ul', null,
      h('li', null, 'Source code, data history and hunt rules: ', extLink(REPO_URL, 'github.com/tstefan-ws/deaddrop-hunter')),
      h('li', null, 'Report a false positive, a new contract or a takedown: ', extLink(ISSUES_URL, 'open a GitHub issue'))));
}
