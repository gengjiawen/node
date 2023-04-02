import {InternalBindingWorker} from "./internalBinding/worker";
import {InternalBindingUtil} from "./internalBinding/util";

declare type TypedArray =
  | Uint8Array
  | Uint8ClampedArray
  | Uint16Array
  | Uint32Array
  | Int8Array
  | Int16Array
  | Int32Array
  | Float32Array
  | Float64Array
  | BigUint64Array
  | BigInt64Array;

  type internalMethods = "async_wrap" | "blob" | "block_list" | "buffer" | "builtins" | "cares_wrap" | "config" | "contextify" | "credentials" | "encoding_binding" | "errors" | "fs" | "fs_dir" | "fs_event_wrap" | "heap_utils" | "http2" | "http_parser" | "inspector" | "js_stream" | "js_udp_wrap" | "messaging" | "module_wrap" | "mksnapshot" | "options" | "os" | "performance" | "permission" | "pipe_wrap" | "process_wrap" | "process_methods" | "report" | "sea" | "serdes" | "signal_wrap" | "spawn_sync" | "stream_pipe" | "stream_wrap" | "string_decoder" | "symbols" | "task_queue" | "tcp_wrap" | "timers" | "trace_events" | "tty_wrap" | "types" | "udp_wrap" | "url" | "util" | "uv" | "v8" | "wasi" | "wasm_web_api" | "watchdog" | "worker" | "zlib"

type StringToType<T extends string> =
  T extends 'util' ? InternalBindingUtil :
    T extends 'worker' ? InternalBindingWorker :
        T extends 'object' ? object : never;


interface Global {
    InternalBindingType<T extends string>(type: T): StringToType<T>
}
