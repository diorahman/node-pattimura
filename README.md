## Node.js binding for Pattimura cipher by [Abraham Ferdinand](https://bitbucket.org/abeinoe/pattimura).

## install

```
$ npm install pattimura
```

## use

```js
var pattimura = require('pattimura');

var encrypted = pattimura.encryptSync(key, encrypted);
pattimura.decryptSync(key, encrypted);

pattimura.encrypt(key, val, function (err, encrypted){
  pattimura.decrypt(key, encrypted, function(err, decrypted){
    console.log(decrypted);
  })
});
```

## license
MIT
