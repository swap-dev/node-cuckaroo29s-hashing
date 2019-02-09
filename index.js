
var bignum = require('bignum');

function getdifficultyfromhash(hash)
{
	var diff1 = bignum('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF', 16);
	var hashcopy = Buffer.from(hash);
	var hashNum = bignum.fromBuffer(hashcopy.reverse());
	return diff1.div(hashNum).toNumber();
}

module.exports = require('bindings')('cuckaroo29s-hashing.node')
module.exports.getdifficultyfromhash = getdifficultyfromhash;

