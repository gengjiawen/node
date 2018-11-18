// META: script=/resources/WebIDLParser.js
// META: script=/resources/idlharness.js

idl_test(
  ['url'],
  [], // no deps
  (idl_array) => {
    idl_array.add_objects({
      URL: ['new URL("http://foo")'],
      URLSearchParams: ['new URLSearchParams("hi=there&thank=you")']
    });
  }
);
