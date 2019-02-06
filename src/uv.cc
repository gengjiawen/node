// Copyright Joyent, Inc. and other Node contributors.
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the
// "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to permit
// persons to whom the Software is furnished to do so, subject to the
// following conditions:
//
// The above copyright notice and this permission notice shall be included
// in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN
// NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
// DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
// OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE
// USE OR OTHER DEALINGS IN THE SOFTWARE.

#include "uv.h"
#include "env-inl.h"
#include "node.h"
#include "node_process.h"
#include "util.h"

namespace node {

namespace per_process {
struct UVError {
  int value;
  const char* name;
  const char* message;
};

// We only expand the macro once here to reduce the amount of code
// generated.
static const struct UVError uv_errors_map[] = {
#define V(name, message) {UV_##name, #name, message},
    UV_ERRNO_MAP(V)
#undef V
};
}  // namespace per_process

namespace {

using v8::Array;
using v8::Context;
using v8::DontDelete;
using v8::FunctionCallbackInfo;
using v8::Integer;
using v8::Isolate;
using v8::Local;
using v8::Map;
using v8::Object;
using v8::PropertyAttribute;
using v8::ReadOnly;
using v8::String;
using v8::Value;

void ErrName(const FunctionCallbackInfo<Value>& args) {
  Environment* env = Environment::GetCurrent(args);
  if (env->options()->pending_deprecation && env->EmitErrNameWarning()) {
    if (ProcessEmitDeprecationWarning(
            env,
            "Directly calling process.binding('uv').errname(<val>) is being"
            " deprecated. "
            "Please make sure to use util.getSystemErrorName() instead.",
            "DEP0119")
            .IsNothing())
      return;
  }
  int err;
  if (!args[0]->Int32Value(env->context()).To(&err)) return;
  CHECK_LT(err, 0);
  const char* name = uv_err_name(err);
  args.GetReturnValue().Set(OneByteString(env->isolate(), name));
}

void GetErrMap(const FunctionCallbackInfo<Value>& args) {
  Environment* env = Environment::GetCurrent(args);
  Isolate* isolate = env->isolate();
  Local<Context> context = env->context();

  Local<Map> err_map = Map::New(isolate);

  size_t errors_len = arraysize(per_process::uv_errors_map);
  for (size_t i = 0; i < errors_len; ++i) {
    const auto& error = per_process::uv_errors_map[i];
    Local<Value> arr[] = {OneByteString(isolate, error.name),
                          OneByteString(isolate, error.message)};
    if (err_map
            ->Set(context,
                  Integer::New(isolate, error.value),
                  Array::New(isolate, arr, arraysize(arr)))
            .IsEmpty()) {
      return;
    }
  }

  args.GetReturnValue().Set(err_map);
}

void Initialize(Local<Object> target,
                Local<Value> unused,
                Local<Context> context,
                void* priv) {
  Environment* env = Environment::GetCurrent(context);
  Isolate* isolate = env->isolate();
  target
      ->Set(env->context(),
            FIXED_ONE_BYTE_STRING(isolate, "errname"),
            env->NewFunctionTemplate(ErrName)
                ->GetFunction(env->context())
                .ToLocalChecked())
      .FromJust();

  // TODO(joyeecheung): This should be deprecated in user land in favor of
  // `util.getSystemErrorName(err)`.
  PropertyAttribute attributes =
      static_cast<PropertyAttribute>(ReadOnly | DontDelete);
  size_t errors_len = arraysize(per_process::uv_errors_map);
  const std::string prefix = "UV_";
  for (size_t i = 0; i < errors_len; ++i) {
    const auto& error = per_process::uv_errors_map[i];
    const std::string prefixed_name = prefix + error.name;
    Local<String> name = OneByteString(isolate, prefixed_name.c_str());
    Local<Integer> value = Integer::New(isolate, error.value);
    target->DefineOwnProperty(context, name, value, attributes).FromJust();
  }

  env->SetMethod(target, "getErrorMap", GetErrMap);
}

}  // anonymous namespace
}  // namespace node

NODE_MODULE_CONTEXT_AWARE_INTERNAL(uv, node::Initialize)
