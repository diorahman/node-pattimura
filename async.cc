#include "async.h"
#include "encrypt-decrypt.h"

enum PattimuraMode {
  ENC, DEC
};

class PattimuraWorker: public Nan::AsyncWorker {
  public:
    PattimuraWorker(Nan::Callback * callback, PattimuraMode mode, unsigned char * key, unsigned char * val, unsigned int len, unsigned int keyLength)
      : Nan::AsyncWorker(callback), mode(mode), key(key), val(val), len(len), keyLength(keyLength) {}
    ~PattimuraWorker() {}

    void Execute() {
      result = new unsigned char[keyLength];
      if (mode == ENC)
        return encrypt(key, val, result, keyLength);
      decrypt(key, val, result, keyLength);
    }

    void HandleOKCallback() {
      Nan::HandleScope scope; 
      v8::Local<v8::Value> argv[] = {
        Nan::Null(),
        Nan::NewBuffer((char *) result, len).ToLocalChecked()
      };
      callback->Call(2, argv);
    }

    void HandleErrorCallback() {
      // we have no error case yet    
    }

  private:
    PattimuraMode mode;
    unsigned char * key;
    unsigned char * val;
    unsigned char * result;
    unsigned int len;
    unsigned int keyLength;
};

NAN_METHOD (EncryptAsync) {
  // encrypt(key, val, function(){})
  v8::Local<v8::Object> key = info[0]->ToObject();
  unsigned char *keyChar = (unsigned char *) node::Buffer::Data(key);
  v8::Local<v8::Object> plain = info[1]->ToObject();
  unsigned char *plainChar = (unsigned char *) node::Buffer::Data(plain);
  Nan::Callback *callback = new Nan::Callback(info[2].As<v8::Function>());
  Nan::AsyncQueueWorker(new PattimuraWorker(callback, ENC, keyChar, plainChar, node::Buffer::Length(plain), node::Buffer::Length(key)));
}

NAN_METHOD (DecryptAsync) {
  // decrypt(key, val, function(){})
  v8::Local<v8::Object> key = info[0]->ToObject();
  unsigned char *keyChar = (unsigned char *) node::Buffer::Data(key);
  v8::Local<v8::Object> encrypted = info[1]->ToObject();
  unsigned char *encryptedChar = (unsigned char *) node::Buffer::Data(encrypted);
  Nan::Callback * callback = new Nan::Callback(info[2].As<v8::Function>());
  Nan::AsyncQueueWorker(new PattimuraWorker(callback, DEC, keyChar, encryptedChar, node::Buffer::Length(encrypted), node::Buffer::Length(key)));
}

