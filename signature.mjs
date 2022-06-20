import { createHash } from 'crypto'

function computeChecksum(data, hashOffset = 0, hashLength) {
   if (hashLength === undefined) { hashLength = data.length; }
   let slice = data.substring( hashOffset, hashLength );
   return createHash('sha256').update(slice).digest('hex');
}

/* To scan a contract, provide it's address and getCode result */
function prepareContract(contractAddress, code) {
  return {contractAddress, code};
}

/* To scan a transaction, provide transaction and receipt */
function prepareTransaction(txn, receipt) {
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
  
  return tcopy;
}

/* Scanner entrypoint, returns false if signature did not match otherwise a result object */
function applySignature(signature, object) {

  // Step 1: apply filter to object
  for (let key of Object.keys(signature.filter)) {
    let v = signature.filter[key];
    
    if (typeof v === 'object' && v !== null) {
      // hash check
      let {length, checksum, hashOffset, hashLength} = v;
      if (object[key].length != length) {
        return { match: false, type: 'length', key, svalue: length, value: object[key].length }
      }
      let dchecksum = computeChecksum( object[key], hashOffset, hashLength );
      if (dchecksum !== checksum) {
        return { match: false, type: 'checksum', key, svalue: checksum, value: dchecksum }
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
  if (signature.signatureType === "transaction") {  r.transactionHash = object.transactionHash; }
  if (signature.signatureType === "contract")    {  r.contractAddress = object.contractAddress; }
  
  return r;
  
}

export { applySignature, prepareContract, prepareTransaction };
