'use strict';

const AWS = require('aws-sdk');

const encrypted = {
  secretPassword: process.env['SECRET_PASSWORD'],
  otherSecretPassword: process.env['OTHER_SECRET_PASSWORD'],
};

let isDecrypted = false;
const decrypted = {};

const processEvent = async event => {
  return {
    statusCode: 200,
    body: JSON.stringify({
      message: 'Successfully decrypted secrets!',
      input: event,
      encrypted,
      decrypted,
    }),
  };
};

module.exports.hello = async (event, context, callback) => {
  if (isDecrypted) {
    return processEvent(event, context, callback);
  } else {
    // Decrypt code should run once and variables stored outside of the function
    // handler so that these are decrypted once per container
    const kms = new AWS.KMS();
    const keys = Object.keys(encrypted);
    await Promise.all(
      keys.map(key => {
        return kms
          .decrypt({ CiphertextBlob: new Buffer(encrypted[key], 'base64') })
          .promise()
          .then(({ Plaintext }) => (decrypted[key] = Plaintext.toString()));
      }),
    );

    isDecrypted = true;

    return processEvent(event, context, callback);
  }
};
