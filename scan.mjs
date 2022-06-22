import { applySignature, prepareContract, downloadTransaction } from './signature.mjs';
import { readFileSync } from 'fs'
import { parse } from 'yaml'
import Web3 from 'web3';

const web3 = new Web3("https://bsc-dataseed1.binance.org");
const argv = process.argv;

(async()=>{

if (argv.length < 5) {
  console.log('Usage: node scan.mjs <malware_yaml> contract <address> ');
  console.log('       node scan.mjs <malware_yaml> block <number> ');
  console.log('       node scan.mjs <malware_yaml> transaction <hash> ');  
} else {
  let data = readFileSync( argv[2], 'utf-8' );
  let malwares = parse(data);

  let op = argv[3];
  let arg = argv[4];

  let targets = [];
    
  if (op === 'contract') {
    let addrs = [arg];
    
    if (arg.substring(0,1) == '@') {
      let data = readFileSync( arg.substring(1), 'utf-8' );
      addrs = data.split('\n');
    }

    console.log('Fetching',addrs.length,'contracts');
    for (let addr of addrs) {
      if (addr == '') { continue; }
      console.log('Fetching contract', addr);    
      let code = await web3.eth.getCode( addr );
      targets.push( prepareContract(addr, code) );
    } 
    
  } else if (op === 'block' || op === 'transaction') {
    // build target transaction list
    let transactions = [arg];

    if (op === 'block') {
      let block = await web3.eth.getBlock( parseInt(arg) );
      transactions = block.transactions;
    } 
        
    // load transactions
    console.log('Fetching',transactions.length,'transactions');
    for (let txnHash of transactions) {
      console.log(txnHash);
      try {
        targets.push( await downloadTransaction(txnHash) );
      } catch(e) {
        console.error('SKIPPED:', e);
      }
    }
  }
   
  if (targets.length === 0) {
    console.error('Unknown scan operation', argv[4],'or nothing to scan.');
  } else {
    let hits = 0;
    for (let target of targets) {
      let match = false;
      for (let sig of malwares.signatures) {
        if (sig.signatureType == 'source') { continue; }
        let res = applySignature( sig, target );
        if (res.match) {
          console.error(target.contractAddress || target.transactionHash, ' MATCHED ',malwares.malwareName, malwares.malwareTags);       
          console.dir(res);
          match = true;
        }
      }
      if (!match) {
        console.log(target.contractAddress || target.transactionHash, 'clean');
      } else {
        hits++;
      }
    }
    
    console.log('Scan found',hits,'matches in',targets.length,'targets');
  }
  
}

})();
