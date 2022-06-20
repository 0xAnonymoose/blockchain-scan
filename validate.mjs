import { applySignature, prepareContract, prepareTransaction } from './signature.mjs';
import { readFileSync } from 'fs'
import { parse } from 'yaml'
import Web3 from 'web3';

const web3 = new Web3("https://bsc-dataseed1.binance.org");
const argv = process.argv;

(async()=>{

if (argv.length < 3) {
  console.log('Usage: node validate.mjs <malware_yaml>');
} else {
  let data = readFileSync( argv[2], 'utf-8' );
  let malwares = parse(data);
  
  for (let sig of malwares.signatures) {
    console.log('---', sig.note);
    
    for (let ex of sig.example) {
      let sample;
      // transaction scan
      if (ex.hasOwnProperty('transactionHash')) {
        let txn = await web3.eth.getTransaction( ex.transactionHash );
        let rcpt = await web3.eth.getTransactionReceipt( ex.transactionHash );
      
        let res = applySignature( sig, prepareTransaction(txn, rcpt) );
        if (res.match) {
          console.log('OK! transactionHash=', ex.transactionHash);
          
          for (let f of Object.keys(ex)) {
            if (ex[f] === res[f]) {
              console.log('OK!   ', f, 'MATCH', ex[f]);
            } else {
              console.error('FAIL   ', f, 'FAIL', ex[f], '!=', res[f]);
            }
          }
        } else {
          console.error('FAIL transactionHash=', ex.transactionHash, JSON.stringify(res));
        }
      }
      // contract scan
      else if (ex.hasOwnProperty('contractAddress')) { 
        let code = await web3.eth.getCode( ex.contractAddress );

        let res = applySignature( sig, prepareContract(ex.contractAddress, code) );
        if (res.match) {
          console.log('OK! contractAddress=', ex.contractAddress);
        } else {
          console.error('FAIL contractAddress=', ex.contractAddress, JSON.stringify(res));
        }
      }
      // unknown example type
      else {
        console.error('FAIL unknown example type');
        return;
      }
    }
  
  }
  
}

})();
