#include "node_dns.h"
#include "base_object-inl.h"
#include "env-inl.h"
#include "node.h"
#include "node_errors.h"
#include "node_mem-inl.h"
#include "util-inl.h"
#include "uv.h"

namespace node {
namespace dns {

using v8::Array;
using v8::Context;
using v8::FunctionCallbackInfo;
using v8::FunctionTemplate;
using v8::Global;
using v8::HandleScope;
using v8::Integer;
using v8::Isolate;
using v8::Local;
using v8::MaybeLocal;
using v8::Name;
using v8::NewStringType;
using v8::Null;
using v8::Object;
using v8::Promise;
using v8::String;
using v8::Value;

#define GETDNS_BASE(ret, name, isolate, ...)                                   \
  do {                                                                         \
    getdns_return_t r = getdns_##name(__VA_ARGS__);                            \
    if (UNLIKELY(r != GETDNS_RETURN_GOOD)) {                                   \
      THROW_ERR_DNS_ERROR(isolate, getdns_get_errorstr_by_id(r));              \
      return ret;                                                              \
    }                                                                          \
  } while (false);

#define GETDNS(name, isolate, ...)                                             \
  GETDNS_BASE(/* empty */, name, isolate, __VA_ARGS__)
#define GETDNSV(name, isolate, ...) GETDNS_BASE({}, name, isolate, __VA_ARGS__)

DNSWrap::DNSWrap(Environment* env, Local<Object> object)
    : AsyncWrap(env, object, PROVIDER_DNSCHANNEL) {
  MakeWeak();

  Isolate* isolate = env->isolate();
  allocator_ = MakeAllocator();
  GETDNS(context_create_with_extended_memory_functions,
         isolate,
         &context_,
         true,
         reinterpret_cast<void*>(&allocator_),
         // convert from getdns allocator signature to libng signature
         [](void* data, size_t size) -> void* {
           Allocator* a = reinterpret_cast<Allocator*>(data);
           return a->malloc(size, a->data);
         },
         [](void* data, void* ptr, size_t size) -> void* {
           Allocator* a = reinterpret_cast<Allocator*>(data);
           return a->realloc(ptr, size, a->data);
         },
         [](void* data, void* ptr) {
           Allocator* a = reinterpret_cast<Allocator*>(data);
           a->free(ptr, a->data);
         });
  GETDNS(extension_set_libuv_loop, isolate, context_, env->event_loop());
  GETDNS(context_set_tls_authentication,
         isolate,
         context_,
         GETDNS_AUTHENTICATION_REQUIRED);
}

DNSWrap::~DNSWrap() {
  getdns_context_destroy(context_);
  CHECK_EQ(current_getdns_memory_, 0);
}

void DNSWrap::MemoryInfo(MemoryTracker* tracker) const {
  // tracker->TrackFieldWithSize("getdns_memory", current_getdns_memory_, "getdns_context");
}

void DNSWrap::CheckAllocatedSize(size_t previous_size) const {
  CHECK_GE(current_getdns_memory_, previous_size);
}

void DNSWrap::IncreaseAllocatedSize(size_t size) {
  current_getdns_memory_ += size;
}

void DNSWrap::DecreaseAllocatedSize(size_t size) {
  current_getdns_memory_ -= size;
}

void DNSWrap::New(const FunctionCallbackInfo<Value>& args) {
  CHECK(args.IsConstructCall());
  Environment* env = Environment::GetCurrent(args);
  new DNSWrap(env, args.This());
}

// static
void DNSWrap::Callback(getdns_context* getdns_context,
                       getdns_callback_type_t cb_type,
                       getdns_dict* response,
                       void* data,
                       getdns_transaction_t tid) {
  DNSWrap* dns = reinterpret_cast<DNSWrap*>(data);
  Isolate* isolate = dns->env()->isolate();
  HandleScope scope(isolate);
  Local<Context> context = dns->env()->context();
  Context::Scope context_scope(context);

  auto cleanup = OnScopeLeave([&]{
    getdns_dict_destroy(response);
  });

  switch (cb_type) {
    case GETDNS_CALLBACK_COMPLETE:
      break;
#define V(name)                                                                \
  case GETDNS_CALLBACK_##name:                                                 \
    dns->RejectTransaction(                                                    \
        tid, ERR_DNS_##name(isolate, GETDNS_CALLBACK_##name##_TEXT));          \
    return;
      V(CANCEL)
      V(TIMEOUT)
      V(ERROR)
#undef V
    default:
      UNREACHABLE();
  }

  {
    uint32_t status;
    GETDNS(dict_get_int, isolate, response, "/status", &status);
    switch (status) {
      case GETDNS_RESPSTATUS_GOOD:
        break;
#define V(name)                                                                \
  case GETDNS_RESPSTATUS_##name:                                               \
    dns->RejectTransaction(                                                    \
        tid, ERR_DNS_##name(isolate, GETDNS_RESPSTATUS_##name##_TEXT));        \
    return;
        V(NO_NAME)
        V(ALL_TIMEOUT)
        V(NO_SECURE_ANSWERS)
        V(ALL_BOGUS_ANSWERS)
#undef V
      default:
        UNREACHABLE();
    }
  }

  char* json = getdns_print_json_dict(response, 0);
  Local<String> result = String::NewFromUtf8(isolate, json).ToLocalChecked();
  free(json);

  dns->ResolveTransaction(tid, result);
}

Local<Value> DNSWrap::RegisterTransaction(getdns_transaction_t tid) {
  Local<Promise::Resolver> p =
      Promise::Resolver::New(env()->context()).ToLocalChecked();
  transactions_[tid].Reset(env()->isolate(), p);
  return p->GetPromise();
}

void DNSWrap::ResolveTransaction(getdns_transaction_t tid, Local<Value> v) {
  auto it = transactions_.find(tid);
  it->second.Get(env()->isolate())->Resolve(env()->context(), v).ToChecked();
  transactions_.erase(it);
}

void DNSWrap::RejectTransaction(getdns_transaction_t tid, Local<Value> v) {
  auto it = transactions_.find(tid);
  it->second.Get(env()->isolate())->Reject(env()->context(), v).ToChecked();
  transactions_.erase(it);
}

// static
void DNSWrap::GetAddresses(const FunctionCallbackInfo<Value>& args) {
  DNSWrap* dns;
  ASSIGN_OR_RETURN_UNWRAP(&dns, args.This());
  Environment* env = dns->env();
  CHECK(args[0]->IsString());
  String::Utf8Value name(env->isolate(), args[0]);
  getdns_dict* extension = nullptr;
  getdns_transaction_t tid;
  GETDNS(address,
         env->isolate(),
         dns->context_,
         *name,
         extension,
         dns,
         &tid,
         Callback);
  args.GetReturnValue().Set(dns->RegisterTransaction(tid));
}

// static
void DNSWrap::GetServices(const FunctionCallbackInfo<Value>& args) {
  DNSWrap* dns;
  ASSIGN_OR_RETURN_UNWRAP(&dns, args.This());
  Environment* env = dns->env();
  CHECK(args[0]->IsString());
  String::Utf8Value name(env->isolate(), args[0]);
  getdns_dict* extension = nullptr;
  getdns_transaction_t tid;
  GETDNS(service,
         env->isolate(),
         dns->context_,
         *name,
         extension,
         dns,
         &tid,
         Callback);
  args.GetReturnValue().Set(dns->RegisterTransaction(tid));
}

static bool ConvertAddress(Isolate* isolate,
                           const char* address,
                           getdns_dict* dict) {
  char address_buffer[sizeof(struct in6_addr)];
  size_t length;
  int family;
  if (uv_inet_pton(AF_INET, address, &address_buffer) == 0) {
    length = sizeof(struct in_addr);
    family = AF_INET;
  } else if (uv_inet_pton(AF_INET6, address, &address_buffer) == 0) {
    length = sizeof(struct in6_addr);
    family = AF_INET6;
  } else {
    THROW_ERR_DNS_ERROR(isolate, "Invalid address");
    return false;
  }

  getdns_bindata address_data{length,
                              reinterpret_cast<uint8_t*>(address_buffer)};
  GETDNSV(dict_util_set_string,
          isolate,
          dict,
          "address_type",
          family == AF_INET ? "IPv4" : "IPv6");
  GETDNSV(dict_set_bindata, isolate, dict, "address_data", &address_data);

  return true;
}

// static
void DNSWrap::GetHostnames(const FunctionCallbackInfo<Value>& args) {
  DNSWrap* dns;
  ASSIGN_OR_RETURN_UNWRAP(&dns, args.This());
  Environment* env = dns->env();

  CHECK(args[0]->IsString());
  String::Utf8Value name(env->isolate(), args[0]);
  getdns_dict* address = getdns_dict_create_with_context(dns->context_);
  auto cleanup = OnScopeLeave([&]() {
    getdns_dict_destroy(address);
  });
  if (!ConvertAddress(env->isolate(), *name, address)) {
    return;
  }

  getdns_dict* extension = nullptr;
  getdns_transaction_t tid;
  GETDNS(hostname,
         env->isolate(),
         dns->context_,
         address,
         extension,
         dns,
         &tid,
         Callback);
  args.GetReturnValue().Set(dns->RegisterTransaction(tid));
}

// static
void DNSWrap::GetGeneral(const FunctionCallbackInfo<Value>& args) {
  DNSWrap* dns;
  ASSIGN_OR_RETURN_UNWRAP(&dns, args.This());
  Environment* env = dns->env();
  CHECK(args[0]->IsString());
  String::Utf8Value name(env->isolate(), args[0]);
  CHECK(args[1]->IsUint32());
  uint16_t type = args[1]->Uint32Value(env->context()).ToChecked();
  getdns_dict* extension = nullptr;
  getdns_transaction_t tid;
  GETDNS(general,
         env->isolate(),
         dns->context_,
         *name,
         type,
         extension,
         dns,
         &tid,
         Callback);
  args.GetReturnValue().Set(dns->RegisterTransaction(tid));
}

// static
void DNSWrap::SetUpstreamRecursiveServers(
    const FunctionCallbackInfo<Value>& args) {
  DNSWrap* dns;
  ASSIGN_OR_RETURN_UNWRAP(&dns, args.This());
  Environment* env = dns->env();

  CHECK(args[0]->IsArray());
  Local<Array> a = args[0].As<Array>();
  uint32_t length = a->Length();

  getdns_list* list = getdns_list_create_with_context(dns->context_);
  auto cleanup = OnScopeLeave([&]() {
    getdns_list_destroy(list);
  });

  for (uint32_t i = 0; i < length; i += 1) {
    getdns_dict* dict = getdns_dict_create_with_context(dns->context_);
    auto cleanup = OnScopeLeave([&]() {
      getdns_dict_destroy(dict);
    });
    Local<Array> server =
        a->Get(env->context(), i).ToLocalChecked().As<Array>();
    String::Utf8Value address(env->isolate(),
                              server->Get(env->context(), 0).ToLocalChecked());
    if (!ConvertAddress(env->isolate(), *address, dict)) {
      return;
    }
    uint32_t port = server->Get(env->context(), 1)
                        .ToLocalChecked()
                        ->Uint32Value(env->context())
                        .ToChecked();
    Local<Value> tls_hostname = server->Get(env->context(), 2).ToLocalChecked();
    if (!tls_hostname->IsUndefined()) {
      GETDNS(dict_set_int, env->isolate(), dict, "tls_port", port);
      String::Utf8Value hostname(env->isolate(), tls_hostname);
      GETDNS(dict_util_set_string,
             env->isolate(),
             dict,
             "tls_auth_name",
             *hostname);
    } else {
      GETDNS(dict_set_int, env->isolate(), dict, "port", port);
    }
    GETDNS(list_set_dict, env->isolate(), list, i, dict);
  }

  GETDNS(context_set_upstream_recursive_servers,
         env->isolate(),
         dns->context_,
         list);
}

// static
void DNSWrap::GetUpstreamRecursiveServers(
    const FunctionCallbackInfo<Value>& args) {
  DNSWrap* dns;
  ASSIGN_OR_RETURN_UNWRAP(&dns, args.This());
  Environment* env = dns->env();

  getdns_list* list;
  auto cleanup = OnScopeLeave([&]() {
    getdns_list_destroy(list);
  });
  GETDNS(context_get_upstream_recursive_servers,
         env->isolate(),
         dns->context_,
         &list);

  char* json = getdns_print_json_list(list, 0);
  Local<String> result = String::NewFromUtf8(env->isolate(), json).ToLocalChecked();
  free(json);

  args.GetReturnValue().Set(result);
}

// static
void DNSWrap::SetDNSTransportList(const FunctionCallbackInfo<Value>& args) {
  DNSWrap* dns;
  ASSIGN_OR_RETURN_UNWRAP(&dns, args.This());
  Environment* env = dns->env();

  CHECK(args[0]->IsArray());
  Local<Array> transports = args[0].As<Array>();
  uint32_t length = transports->Length();

  std::vector<getdns_transport_list_t> transport_list(length);
  for (uint32_t i = 0; i < length; i += 1) {
    getdns_transport_list_t transport =
        static_cast<getdns_transport_list_t>(transports->Get(env->context(), i)
                                                 .ToLocalChecked()
                                                 ->Uint32Value(env->context())
                                                 .ToChecked());
    transport_list[i] = transport;
  }

  GETDNS(context_set_dns_transport_list,
         env->isolate(),
         dns->context_,
         length,
         &transport_list[0]);
}

// static
void DNSWrap::CancelAllTransactions(const FunctionCallbackInfo<Value>& args) {
  DNSWrap* dns;
  ASSIGN_OR_RETURN_UNWRAP(&dns, args.This());
  std::vector<getdns_transaction_t> transactions;
  for (auto& t : dns->transactions_) {
    transactions.push_back(t.first);
  }
  for (auto& t : transactions) {
    GETDNS(cancel_callback, dns->env()->isolate(), dns->context_, t);
  }
  dns->transactions_.clear();
}

static void Initialize(Local<Object> target,
                       Local<Value> unused,
                       Local<Context> context,
                       void* priv) {
  Environment* env = Environment::GetCurrent(context);

  Local<FunctionTemplate> tmpl = env->NewFunctionTemplate(DNSWrap::New);
  auto dns_wrap_string = FIXED_ONE_BYTE_STRING(env->isolate(), "DNSWrap");
  tmpl->InstanceTemplate()->SetInternalFieldCount(DNSWrap::kInternalFieldCount);
  tmpl->SetClassName(dns_wrap_string);

  env->SetProtoMethod(tmpl, "getAddresses", DNSWrap::GetAddresses);
  env->SetProtoMethod(tmpl, "getServices", DNSWrap::GetServices);
  env->SetProtoMethod(tmpl, "getHostnames", DNSWrap::GetHostnames);
  env->SetProtoMethod(tmpl, "getGeneral", DNSWrap::GetGeneral);

  env->SetProtoMethod(tmpl,
                      "setUpstreamRecursiveServers",
                      DNSWrap::SetUpstreamRecursiveServers);
  env->SetProtoMethod(tmpl,
                      "getUpstreamRecursiveServers",
                      DNSWrap::GetUpstreamRecursiveServers);
  env->SetProtoMethod(
      tmpl, "setDNSTransportList", DNSWrap::SetDNSTransportList);

  env->SetProtoMethod(
      tmpl, "cancelAllTransactions", DNSWrap::CancelAllTransactions);

  target
      ->Set(env->context(),
            dns_wrap_string,
            tmpl->GetFunction(context).ToLocalChecked())
      .ToChecked();

#define V(name)                                                                \
  target                                                                       \
      ->Set(env->context(),                                                    \
            FIXED_ONE_BYTE_STRING(env->isolate(), #name),                      \
            Integer::New(env->isolate(), name))                                \
      .ToChecked();

  V(GETDNS_TRANSPORT_UDP)
  V(GETDNS_TRANSPORT_TCP)
  V(GETDNS_TRANSPORT_TLS)
#undef V
}

}  // namespace dns
}  // namespace node

NODE_MODULE_CONTEXT_AWARE_INTERNAL(dns, node::dns::Initialize)
