import { createHash } from 'crypto'
import web3 from './blockchain.mjs'

function computeChecksum(data, hashOffset = 0, hashEnd) {
   if (hashEnd === undefined) { hashEnd = data.length; }
   let slice = data.substring( hashOffset, hashEnd );
   return createHash('sha256').update(slice).digest('hex');
}

/* To scan a contract, provide it's address and getCode result */
function prepareContract(contractAddress, code) {
  return {contractAddress, code};
}

/* To scan a transaction, provide transaction and receipt */
function prepareTransaction(txn, receipt, code) {
  function lcStrings(x) { return typeof x === 'string' ? x.toLowerCase() : x; }
  
  // duplicate the transaction object, lowrecase all strings
  let tcopy = {}
  for (let f of Object.keys(txn)) {
    tcopy[f] = lcStrings( txn[f] );
  }
  
  // merge receipt fields
  const rfields = [ 'contractAddress', 'cumulativeGasUsed', 'gasUsed', 'logsBloom', 'logs', 'status', 'transactionHash' ];
  for (let f of rfields) {
    tcopy[f] = lcStrings( receipt[f] );
  }
  
  // code (optional)
  if (code) {
    tcopy.code = code;
  }
  
  return tcopy;
}

/* Download transaction from blockchain helper */
async function downloadTransaction( txnHash ) {
   let txn = await web3.eth.getTransaction( txnHash );
   let rcpt = await web3.eth.getTransactionReceipt( txnHash );
   let code = null;   
   if (rcpt.contractAddress && txn.to === null) {
     code = await web3.eth.getCode( rcpt.contractAddress );
   }
   return prepareTransaction(txn, rcpt, code);
}

/* Scanner entrypoint, returns false if signature did not match otherwise a result object */
function applySignature(signature, object) {

  // Step 1: apply filter to object
  for (let key of Object.keys(signature.filter)) {
    let v = signature.filter[key];
    
    if (!object.hasOwnProperty(key)) {
      return { match: false, type: 'exists', key }
    }
    
    if (typeof v === 'object' && v !== null) {
      // method check
      if (v.startsWith) {
        let ostart = object[key].substring(0, v.startsWith.length);
        if (ostart != v.startsWith) {
          return { match: false, type: 'startsWith', key, svalue: v.startsWith, value: ostart }
        }
      }
      // hash check      
      else if (v.checksums) {
        let {length, checksums} = v;
        if (object[key].length != length) {
          return { match: false, type: 'length', key, svalue: length, value: object[key].length }
        }
        for (let chk of checksums) {
          let dchecksum = computeChecksum( object[key], chk.offset, chk.end );
          if (dchecksum !== chk.sha256) {
            return { match: false, type: 'checksum', key, svalue: chk.sha256, value: dchecksum }
          }
        }
      }
      // bad check?
      else {
        return { match: false, type: 'bad_check' }
      }
    } else {
      // value check
      let d = typeof object[key] === 'string' ? object[key].toLowerCase() : object[key];
      if (d !== v) {
        return { match: false, type: 'value', key, svalue: v, value: object[key] }
      }
    }
  }
  
  // Step 2: matched, build output.
  let r = { detectedSchema: signature.outputSchema, match: true }
  if (signature.hasOwnProperty('outputMap')) {
    for (let key of Object.keys(signature.outputMap)) {
      r[ key ] = object[ signature.outputMap[key] ];
    }
  }
  if (object.transactionHash) {  r.transactionHash = object.transactionHash; }
  if (object.contractAddress) {  r.contractAddress = object.contractAddress; }
  
  return r;
  
}

export { applySignature, prepareContract, prepareTransaction, downloadTransaction };
