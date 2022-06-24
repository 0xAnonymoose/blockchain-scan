import { applySignature, prepareContract, downloadTransaction } from './signature.mjs';
import { readFileSync, writeFileSync } from 'fs'
import { parse } from 'yaml'
import Web3 from 'web3';

const web3 = new Web3("https://bsc-dataseed1.binance.org");
const argv = process.argv;

function _saveCache(fname, data) { 
  writeFileSync(fname, data);
}

function _loadCache(fname) {
  try {
     let rawdata = readFileSync(fname, 'utf-8');
     return rawdata;
  } catch(err) {
     return null;
  }
}

async function cachedTransaction( txnHash ) {
  let c = _loadCache('cache/'+txnHash+'.json');
  if (c != null) { return JSON.parse(c); }
  c = await downloadTransaction(txnHash);
  _saveCache('cache/'+txnHash+'.json', JSON.stringify(c) );
  return c;
}

async function loadTargetTransactions(transactions) {
  let targets = [];
  
  console.log('Fetching',transactions.length,'transactions');
  for (let txnHash of transactions) {
    console.log(txnHash);
    try {
      targets.push( await cachedTransaction(txnHash) );
    } catch(e) {
      console.error('ERROR:', e);
    }
  }
    
  return targets;
}

async function cachedContract( addr ) {
  let c = _loadCache('cache/'+addr+'.hex');
  if (c != null) { return prepareContract(addr,c); }
  c = await web3.eth.getCode(addr);
  _saveCache('cache/'+addr+'.hex', c);
  return prepareContract(addr,c);
}

async function loadTargetContracts (addrs) {
  let targets = [];
  
  console.log('Fetching',addrs.length,'contracts');
  for (let addr of addrs) {
    if (addr == '') { continue; }
    console.log(addr);    
    targets.push( await cachedContract(addr) );
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

    targets = await loadTargetContracts(addrs);

  } else if (op === 'block' || op === 'transaction') {
    // build target transaction list
    let transactions = [arg];

    if (op === 'block') {
      let block = await web3.eth.getBlock( parseInt(arg) );
      transactions = block.transactions;
    } 
        
    // load transactions
    targets = await loadTargetTransactions(transactions);

  } else if (op == 'validate') {
    let deploys = parse(readFileSync( arg, 'utf-8' ));
    
    // load both contracts and transactions
    targets = [...await loadTargetTransactions(Object.keys(deploys.transactions)),
               ...await loadTargetContracts(Object.keys(deploys.contracts))];
     
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
          console.error(target.contractAddress || target.transactionHash, ' MATCHED ',malwares.malwareName, malwares.malwareTags, JSON.stringify(res));       
          match = true;
          break;
        }
      }

      // did we expected to match? (validate)
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
          console.error('FAIL   expected to match ', target.transactionHash || target.contractAddress);
        } else {
          console.log(target.transactionHash || target.contractAddress, 'clean');
        }
      } else {
        hits++;
      }
    }
    
    console.log('Scan found',hits,'matches in',targets.length,'targets');
  }
  
}

})();
