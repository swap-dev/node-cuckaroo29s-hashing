
var bignum = require('bignum');

function getdifficultyfromhash(hash)
{
	var diff1 = bignum('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF', 16);
	var hashNum = bignum.fromBuffer(hash.reverse());
	return diff1.div(hashNum);
}

module.exports = require('bindings')('cuckaroo29s-hashing.node')
module.exports.getdifficultyfromhash = getdifficultyfromhash;

