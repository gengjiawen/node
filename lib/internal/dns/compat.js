'use strict';

const {
  ArrayPrototypeFilter,
  ArrayPrototypeMap,
  ArrayPrototypeSort,
  JSONParse,
} = primordials;

const { DNSWrap } = internalBinding('dns');
const { dnsException } = require('internal/errors');
const { AsyncResource } = require('async_hooks');

class ReqWrap {
  #resource;
  #oncomplete;
  constructor(name) {
    this.#resource = new AsyncResource(name);
  }

  set oncomplete(f) {
    this.#oncomplete = function(...args) {
      try {
        return this.#resource.runInAsyncScope(f, this, ...args);
      } finally {
        this.#resource.emitDestroy();
      }
    };
  }

  get oncomplete() {
    return this.#oncomplete;
  }
}

class QueryReqWrap extends ReqWrap {
  constructor() {
    super('QUERYREQWRAP');
  }
}

class GetAddrInfoReqWrap extends ReqWrap {
  constructor() {
    super('GETADDRINFOREQWRAP');
  }
}

class GetNameInfoReqWrap extends ReqWrap {
  constructor() {
    super('GETNAMEINFOREQWRAP');
  }
}

[
  ['Any', 255],
  ['A', 1],
  ['Aaaa', 28],
  ['Caa', 257],
  ['Cname', 5],
  ['Mx', 15],
  ['Ns', 2],
  ['Txt', 16],
  ['Srv', 33],
  ['Ptr', 12],
  ['Naptr', 35],
  ['Soa', 6],
].forEach(({ 0: name, 1: rr }) => {
  const bindingName = `query${name}`;
  DNSWrap.prototype[bindingName] = function(req, hostname) {
    this.getGeneral(hostname, rr)
      .then((json) => {
        const data = JSONParse(json);
        switch (name) {
          case 'Any':
            break;
          case 'A': {
            const addresses = req.ttl ?
              ArrayPrototypeMap(
                data.replies_tree[0].answer,
                (a) => ({ ttl: a.ttl, address: a.rdata.ipv4_address })) :
              ArrayPrototypeMap(
                data.replies_tree[0].answer,
                (a) => a.rdata.ipv4_address);
            req.oncomplete(null, addresses);
            break;
          }
          case 'Aaaa': {
            const addresses = req.ttl ?
              ArrayPrototypeMap(
                data.replies_tree[0].answer,
                (a) => ({ ttl: a.ttl, address: a.rdata.ipv6_address })) :
              ArrayPrototypeMap(
                data.replies_tree[0].answer,
                (a) => a.rdata.ipv6_address);
            req.oncomplete(null, addresses);
            break;
          }
          case 'Caa':
            req.oncomplete(null, ArrayPrototypeMap(
              data.replies_tree[0].answer,
              (a) => ({
                critical: a.rdata.flags,
                [a.rdata.tag]: a.rdata.value,
              })));
            break;
          case 'Cname':
            req.oncomplete(null, ArrayPrototypeMap(
              data.replies_tree[0].answer, (a) => a.rdata.cname));
            break;
          case 'Mx':
            req.oncomplete(null, ArrayPrototypeMap(
              data.replies_tree[0].answer, (a) => ({
                priority: a.rdata.preference,
                exchange: a.rdata.exchange,
              })));
            break;
          case 'Ns':
            req.oncomplete(null, ArrayPrototypeMap(
              data.replies_tree[0].answer, (a) => a.rdata.nsdname));
            break;
          case 'Txt':
            req.oncomplete(null, ArrayPrototypeMap(
              data.replies_tree,
              (t) => ArrayPrototypeMap(
                t.answer,
                (a) => a.rdata.txt_strings)));
            break;
          case 'Srv':
            req.oncomplete(null, ArrayPrototypeMap(
              data.replies_tree[0].answer, (a) => ({
                priority: a.rdata.priority,
                weight: a.rdata.weight,
                port: a.rdata.port,
                name: a.rdata.name,
              })));
            break;
          case 'Ptr':
            req.oncomplete(null, ArrayPrototypeMap(
              data.replies_tree[0].answer, (a) => a.rdata.ptrname));
            break;
          case 'Naptr':
            req.oncomplete(null, ArrayPrototypeMap(
              data.replies_tree[0].answer, (a) => ({
                flags: a.rdata.flags,
                service: a.rdata.service,
                regexp: a.rdata.regexp,
                replacement: a.rdata.replacement,
                order: a.rdata.order,
                preference: a.rdata.preference,
              })));
            break;
          case 'Soa':
            req.oncomplete(null, ArrayPrototypeMap(
              data.replies_tree[0].answer, (a) => ({
                nsname: a.rdata.nsname,
                hostmaster: a.rdata.hostmaster,
                serial: a.rdata.serial,
                refresh: a.rdata.refresh,
                retry: a.rdata.retry,
                expire: a.rdata.expire,
                minttl: a.rdata.minttl,
              })));
            break;
          default:
            break;
        }
      })
      .catch((e) => {
        req.oncomplete(dnsException(e, bindingName, name));
      });
  };
});

DNSWrap.prototype.getHostByAddr = function(req, address) {
  this.getHostnames(address)
    .then((v) => {
      req.oncomplete(null, v);
    })
    .catch((e) => {
      req.oncomplete(dnsException(e, 'getHostByAddr', address));
    });
};

let implicitResolver;
function getImplicitResolver() {
  if (!implicitResolver) {
    implicitResolver = new DNSWrap();
  }
  return implicitResolver;
}

function getaddrinfo(req, hostname, family, hints, verbatim) {
  getImplicitResolver()
    .getAddresses(hostname)
    .then((json) => {
      const data = JSONParse(json);
      let addresses = data.just_address_answers;
      if (!verbatim) {
        ArrayPrototypeSort(addresses, (a, b) => {
          if (a.address_type === b.address_type) {
            return 0;
          }
          if (a.address_type === 'IPv4' && b.address_type === 'IPv6') {
            return -1;
          }
          return 1;
        });
      }
      if (family !== 0) {
        const type = { 4: 'IPv4', 6: 'IPv6' }[family];
        addresses = ArrayPrototypeFilter(
          addresses, (a) => a.address_type === type);
      }
      addresses = ArrayPrototypeMap(addresses, (a) => a.address_data);
      req.oncomplete(null, addresses);
    })
    .catch((e) => {
      req.oncomplete(dnsException(e, 'getaddrinfo', hostname));
    });
}

function getnameinfo(req, address, port) {
  getImplicitResolver()
    .getServices(address)
    .then((json) => {
      const data = JSONParse(json);
      req.oncomplete(null, data);
    })
    .catch((e) => {
      req.oncomplete(dnsException(e, 'getnameinfo', address));
    });
}

module.exports = {
  QueryReqWrap,
  GetAddrInfoReqWrap,
  GetNameInfoReqWrap,
  getaddrinfo,
  getnameinfo,
};
