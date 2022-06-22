# blockchain-scan

Real-time and On-demand malware scanning for block-chain.

Use Node 16 to run these scripts.

## malware.yaml

Docs TODO, for now see `blockchain-malware` repository in the `samples/` directory

## signature.mjs

MVP implementation.

`function prepareContract(contractAddress, code)`  turn contract address and code into a scannable object

`function prepareTransaction(txn, receipt)` turn transaction and receipt into a scannable object

`function applySignature(signature, object)` perform scan

## validate.mjs

MVP validator for malware.yaml, ensures that all examples provided match the signatures.

`node validate.mjs [path/to/malware.yaml]`

Sample output if all is well:

```
--- Funder wallet creates puppet deployers
OK! transactionHash= 0xe015de2312ad1426c9b4b4dea1c000c849007b0c9d6105bb8969bba1322ec440
OK!    transactionHash MATCH 0xe015de2312ad1426c9b4b4dea1c000c849007b0c9d6105bb8969bba1322ec440
OK!    detectedSchema MATCH puppet
OK!    puppetCreated MATCH 0xf44855be396466c5f8867c01621a6c326052a729
OK!    puppetMaster MATCH 0xd93408ffe8027430bcf7b4151d0c036fd614de33
OK! transactionHash= 0x7673c675f86216405708b8edfa1a29b7618fdb252cabe52dfd61d936410ee64f
OK!    transactionHash MATCH 0x7673c675f86216405708b8edfa1a29b7618fdb252cabe52dfd61d936410ee64f
OK!    detectedSchema MATCH puppet
OK!    puppetCreated MATCH 0x34224299a0e512ac5d30c646424bb221e989a1ad
OK!    puppetMaster MATCH 0xd93408ffe8027430bcf7b4151d0c036fd614de33
--- Rugpull contract deploy check
OK! transactionHash= 0x896be5e7ba3bb6041e698a8e83ad49cea947f5f6e631033ccc225b46b3bc951f
OK!    transactionHash MATCH 0x896be5e7ba3bb6041e698a8e83ad49cea947f5f6e631033ccc225b46b3bc951f
OK!    detectedSchema MATCH malware
OK!    malwareContract MATCH 0x7fa1a7b22c9b45a1f3c7f354f797a9294f352816
OK!    malwareDeployer MATCH 0xf44855be396466c5f8867c01621a6c326052a729
OK! transactionHash= 0xb09c6caabf46ade9845e513e9a446f35bf86e9ff97278e6a5d5b73ed558d7f45
OK!    transactionHash MATCH 0xb09c6caabf46ade9845e513e9a446f35bf86e9ff97278e6a5d5b73ed558d7f45
OK!    detectedSchema MATCH malware
OK!    malwareContract MATCH 0xe21bba7bb966644248cbf4415241a49d242bdc63
OK!    malwareDeployer MATCH 0x34224299a0e512ac5d30c646424bb221e989a1ad
--- Rugpull contract runtime check
OK! contractAddress= 0x7fa1a7b22c9b45a1f3c7f354f797a9294f352816
OK! contractAddress= 0xe21bba7bb966644248cbf4415241a49d242bdc63
```

## scan.mjs

MVP command-line scanner for blocks, transactions and contract

### scan a single contract

`node scan.mjs ../blockchain-malware/samples/Rugpull.aifjoanvls/malware.yaml contract 0xE89268d74CB68cca2E60d7bD39Ed68D5cE5D6900`

### scan a file of contracts

`node scan.mjs ../blockchain-malware/samples/Rugpull.aifjoanvls/malware.yaml contract @tests/contract_Rugpull.aifjoanvls`

### scan a block

`node scan.mjs ../blockchain-malware/samples/Rugpull.aifjoanvls/malware.yaml block 18774457`

### scan a transaction

`node scan.mjs ../blockchain-malware/samples/Rugpull.aifjoanvls/malware.yaml transaction 0x896be5e7ba3bb6041e698a8e83ad49cea947f5f6e631033ccc225b46b3bc951f`

Sample output:

```
Fetching 1 transactions
0x896be5e7ba3bb6041e698a8e83ad49cea947f5f6e631033ccc225b46b3bc951f
0x7fa1a7b22c9b45a1f3c7f354f797a9294f352816  MATCHED  Rugpull.aifjoanvls [ 'backdoor.mint' ]
{
  detectedSchema: 'malware',
  match: true,
  transactionHash: '0x896be5e7ba3bb6041e698a8e83ad49cea947f5f6e631033ccc225b46b3bc951f',
  contractAddress: '0x7fa1a7b22c9b45a1f3c7f354f797a9294f352816'
}
Scan found 1 matches in 1 targets
```
