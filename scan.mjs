import { applySignature, downloadContract, downloadTransaction } from './signature.mjs';
import { readFileSync } from 'fs'
import { parse } from 'yaml'
import Web3 from 'web3';

const web3 = new Web3("https://bsc-dataseed1.binance.org");
const argv = process.argv;

async function prepareTransactions(transactions) {
  let targets = [];
  
  console.log('Fetching',transactions.length,'transactions');
  for (let txnHash of transactions) {
    console.log(txnHash);
    try {
      targets.push( await downloadTransaction(txnHash) );
    } catch(e) {
      console.error('ERROR:', e);
    }
  }
    
  return targets;
}

async function prepareContracts (addrs) {
  let targets = [];
  
  console.log('Fetching',addrs.length,'contracts');
  for (let addr of addrs) {
    if (addr == '') { continue; }
    console.log(addr);    
    targets.push( await downloadContract(addr) );
  } 
    
  return targets;
}

(async()=>{

if (argv.length < 5) {
  console.log('Usage: node scan.mjs <malware_yaml> contract <address> ');
  console.log('       node scan.mjs <malware_yaml> block <number> ');
  console.log('       node scan.mjs <malware_yaml> transaction <hash> '); 
  console.log('       node scan.mjs <malware_yaml> validate <maldeploys_yaml> ');   
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

    targets = await prepareContracts(addrs);

  } else if (op === 'block' || op === 'transaction') {
    // build target transaction list
    let transactions = [arg];

    if (op === 'block') {
      let block = await web3.eth.getBlock( parseInt(arg) );
      transactions = block.transactions;
    } 
        
    // load transactions
    targets = await prepareTransactions(transactions);

  } else if (op == 'validate') {
    let deploys = parse(readFileSync( arg, 'utf-8' ));
    
    // load both contracts and transactions
    targets = [...await prepareTransactions(Object.keys(deploys.transactions)),
               ...await prepareContracts(Object.keys(deploys.contracts))];
     
    // annotate with expected results          
    for (let target of targets) {
      if (target.hasOwnProperty('transactionHash')) {
        target._expected = deploys.transactions[target.transactionHash];
      } else {
        if (deploys.contracts[target.contractAddress]) { 
          target._expected = deploys.contracts[target.contractAddress];
        } else {
          target._expected = { match: true };
        }
      }      
    }
  }
   
  if (targets.length === 0) {
    console.error('Unknown scan operation', argv[4],'or nothing to scan.');
  } else {
    let hits = 0;
    for (let target of targets) {
        
      let match = false;
      let res;
      for (let sig of malwares.signatures) {
        if (sig.signatureType == 'source') { continue; }
        res = applySignature( sig, target );
        if (res.match) {
          console.error(target.contractAddress || target.transactionHash, ' MATCHED ',malwares.malwareName, malwares.malwareTags);       
          console.dir(res);
          match = true;
          break;
        }
      }

      if (target.hasOwnProperty('_expected') && match) {
        let ex = target._expected;
        for (let f of Object.keys(ex)) {
          if (ex[f] === res[f]) {
            console.log('OK!   ', f, 'MATCH', ex[f]);
          } else {
            console.error('FAIL   ', f, 'FAIL', ex[f], '!=', res[f]);
          }
        }
      }
          
      if (!match) {
        if (target.hasOwnProperty('_expected')) {
          console.error('FAIL   expected to match');
        } else {
          console.log(target.contractAddress || target.transactionHash, 'clean');
        }
      } else {
        hits++;
      }
    }
    
    console.log('Scan found',hits,'matches in',targets.length,'targets');
  }
  
}

})();
