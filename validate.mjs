import { applySignature, prepareContract, downloadTransaction } from './signature.mjs';
import { readFileSync } from 'fs'
import { parse } from 'yaml'
import web3 from './blockchain.mjs'

const argv = process.argv;

(async()=>{

if (argv.length < 3) {
  console.log('Usage: node validate.mjs <malware_yaml>');
} else {
  let data = readFileSync( argv[2], 'utf-8' );
  let malwares = parse(data);
  
  for (let sig of malwares.signatures) {
    console.log('---', sig.signatureType, ':', sig.note);
    if (!sig.hasOwnProperty('example')) { continue; }
    for (let ex of sig.example) {
      let sample;
      // test transaction scan
      if (ex.hasOwnProperty('transactionHash')) {
      
        let res = applySignature( sig, await downloadTransaction(ex.transactionHash) );
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
      
      // test contract scan
      if (ex.hasOwnProperty('contractAddress')) { 
        let code = await web3.eth.getCode( ex.contractAddress );

        let res = applySignature( sig, prepareContract(ex.contractAddress, code) );
        if (res.match) {
          console.log('OK! contractAddress=', ex.contractAddress);
        } else {
          console.error('FAIL contractAddress=', ex.contractAddress, JSON.stringify(res));
        }
      }

    }
  
  }
  
}

})();
