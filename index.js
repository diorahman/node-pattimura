var pattimura = require('bindings')('pattimura.node');
var KEY_BITS_LENGTH = [128, 192, 256];
function validate(key, val) {
  if (!(typeof key == 'string' || key instanceof Buffer))
    return new TypeError('Key is String or Buffer.');

  if (!(typeof val == 'string' || val instanceof Buffer))
    return new TypeError('Value is String or Buffer.');
  
  var len = key.length * 8;
  if (KEY_BITS_LENGTH.indexOf(len) < 0)
    throw new RangeError('Key should be 128, 192 or 256 bits');
  return [key, val];
}

function noop() {}

exports.encryptSync = function(key, val) {
  return pattimura.encryptSync.apply(this, validate(key, val));
}

exports.decryptSync = function(key, val) {
  return pattimura.decryptSync.apply(this, validate(key, val));
}

exports.encrypt = function(key, val, cb) {
  var args = validate(key, val);
  if (!cb || typeof cb != 'function')
    cb = noop;
  pattimura.encryptAsync(key, val, cb);
}

exports.decrypt = function(key, val, cb) {
  var args = validate(key, val);
  if (!cb || typeof cb != 'function')
    cb = noop;
  pattimura.decryptAsync(key, val, cb);
}
