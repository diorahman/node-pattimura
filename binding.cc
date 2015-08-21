#include <nan.h>
#include "sync.h"
#include "async.h"

NAN_MODULE_INIT(InitAll) {
  Nan::Set(target, Nan::New<v8::String>("encryptSync").ToLocalChecked(),
    Nan::GetFunction(Nan::New<v8::FunctionTemplate>(EncryptSync)).ToLocalChecked());
  Nan::Set(target, Nan::New<v8::String>("decryptSync").ToLocalChecked(),
    Nan::GetFunction(Nan::New<v8::FunctionTemplate>(DecryptSync)).ToLocalChecked());
  Nan::Set(target, Nan::New<v8::String>("encryptAsync").ToLocalChecked(),
    Nan::GetFunction(Nan::New<v8::FunctionTemplate>(EncryptAsync)).ToLocalChecked());
  Nan::Set(target, Nan::New<v8::String>("decryptAsync").ToLocalChecked(),
    Nan::GetFunction(Nan::New<v8::FunctionTemplate>(DecryptAsync)).ToLocalChecked());
}

NODE_MODULE(addon, InitAll)
