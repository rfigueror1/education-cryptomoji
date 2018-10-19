import {
  Transaction,
  TransactionHeader,
  Batch,
  BatchHeader,
  BatchList
} from 'sawtooth-sdk/protobuf';
import { createHash } from 'crypto';
import { getPublicKey, sign } from './signing.js';
import { encode } from './encoding.js';


const FAMILY_NAME = 'cryptomoji';
const FAMILY_VERSION = '0.1';
const NAMESPACE = '5f4d76';

/**
 * A function that takes a private key and a payload and returns a new
 * signed Transaction instance.
 *
 * Hint:
 *   Remember ProtobufJS has two different APIs for encoding protobufs
 *   (which you'll use for the TransactionHeader) and for creating
 *   protobuf instances (which you'll use for the Transaction itself):
 *     - TransactionHeader.encode({ ... }).finish()
 *     - Transaction.create({ ... })
 *
 *   Also, don't forget to encode your payload!
 */
export const createTransaction = (privateKey, payload) => {
  // Enter your solution here
  var payloadBytes = encode(payload);

  //In cryptography, In cryptography, a nonce is an arbitrary number that can be used just once. 
  //It is similar in spirit to a nonce word, hence the name. 
  //It is often a random or pseudo-random number issued in an authentication protocol to 
  //ensure that old communications cannot be reused in replay attacks.

  var transactionHeader = TransactionHeader.encode({familyName:FAMILY_NAME,
   familyVersion:FAMILY_VERSION,
   familyName: FAMILY_NAME, 
   nameSpace:NAMESPACE,
   signerPublicKey:getPublicKey(privateKey),
   batcherPublicKey: getPublicKey(privateKey),
   inputs:[ NAMESPACE ],
   outputs: [ NAMESPACE ],
   nonce: (Math.random() * 10 ** 18).toString(36),
   payloadSha512: createHash('sha512').update(payloadBytes).digest('hex')
  }).finish()

  const signature = sign(privateKey, transactionHeader)

  const transaction = Transaction.create({
    header: transactionHeader,
    headerSignature: signature,
    payload: payloadBytes
  })

  return transaction;
};

/**
 * A function that takes a private key and one or more Transaction instances
 * and returns a signed Batch instance.
 *
 * Should accept both multiple transactions in an array, or just one
 * transaction with no array.
 */
export const createBatch = (privateKey, transactions) => {
  // Your code here

  if (!Array.isArray(transactions)) {
    transactions = [ transactions ];
  }

  const batchHeaderBytes = BatchHeader.encode({
    signerPublicKey: getPublicKey(privateKey),
    transactionIds: transactions.map((txn) => txn.headerSignature),
  }).finish()

  const signature = sign(privateKey, batchHeaderBytes)

  return Batch.create({
    header: batchHeaderBytes,
    headerSignature: signature,
    transactions: transactions
  });

};

/**
 * A fairly simple function that takes a one or more Batch instances and
 * returns an encoded BatchList.
 *
 * Although there isn't much to it, axios has a bug when POSTing the generated
 * Buffer. We've implemented it for you, transforming the Buffer so axios
 * can handle it.
 */
export const encodeBatches = batches => {
  if (!Array.isArray(batches)) {
    batches = [ batches ];
  }
  const batchList = BatchList.encode({ batches }).finish();

  // Axios will mishandle a Uint8Array constructed with a large ArrayBuffer.
  // The easiest workaround is to take a slice of the array.
  return batchList.slice();
};

/**
 * A convenince function that takes a private key and one or more payloads and
 * returns an encoded BatchList for submission. Each payload should be wrapped
 * in a Transaction, which will be wrapped together in a Batch, and then
 * finally wrapped in a BatchList.
 *
 * As with the other methods, it should handle both a single payload, or
 * multiple payloads in an array.
 */
export const encodeAll = (privateKey, payloads) => {
  // Your code here
  if (!Array.isArray(payloads)) {
    payloads = [ payloads ];
  }
  var transactions = payloads.map( (payload) => createTransaction(privateKey, payload));
  var batch = transactions.map( () => createBatch(privateKey, transactions) );
  var batchList = encodeBatches(batch)
  return batchList;

};
