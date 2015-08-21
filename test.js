var pattimura = require('./');

var key = new Buffer([0, 0, 0, 0, 0 , 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
var plain = new Buffer([0, 0, 0, 0, 0 , 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);

describe('Pattimura in action', function() {
  it('should encrypt and decrypt zeros synchronously', function() {
    var encrypted = pattimura.encryptSync(key, plain);
    var decrypted = pattimura.decryptSync(key, encrypted);
    decrypted.should.deepEqual(plain);
  });
  
  it('should encrypt and decrypt zeros asynchronously', function(done) {
    var encrypted = pattimura.encrypt(key, plain, function(err, encrypted) {
      if (err)
        return done(err);
      pattimura.decrypt(key, encrypted, function(err, decrypted) {
        if (err)
          return done(err);
        done();
      });
    });
  });
});

