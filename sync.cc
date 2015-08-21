#include "sync.h"
#include "encrypt-decrypt.h"

// encryptSync(key, plain)
NAN_METHOD(EncryptSync) {
  v8::Local<v8::Object> key = info[0]->ToObject();
  unsigned char *keyChar = (unsigned char *) node::Buffer::Data(key);
  v8::Local<v8::Object> plain = info[1]->ToObject();
  unsigned char *plainChar = (unsigned char *) node::Buffer::Data(plain);
  unsigned char *encrypted = new unsigned char[node::Buffer::Length(plain)];
  encrypt(keyChar, plainChar, encrypted, node::Buffer::Length(key));
  info.GetReturnValue().Set(Nan::NewBuffer((char *) encrypted, node::Buffer::Length(plain)).ToLocalChecked());
}

// decrypt(key, encrypted)
NAN_METHOD(DecryptSync) {
  v8::Local<v8::Object> key = info[0]->ToObject();
  unsigned char *keyChar = (unsigned char *) node::Buffer::Data(key);
  v8::Local<v8::Object> encrypted = info[1]->ToObject();
  unsigned char *encryptedChar = (unsigned char *) node::Buffer::Data(encrypted);
  unsigned char *decrypted = new unsigned char[node::Buffer::Length(encrypted)];
  decrypt(keyChar, encryptedChar, decrypted, node::Buffer::Length(key));
  info.GetReturnValue().Set(Nan::NewBuffer((char *) decrypted, node::Buffer::Length(encrypted)).ToLocalChecked());
}
