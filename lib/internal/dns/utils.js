'use strict';

const {
  ArrayIsArray,
  ArrayPrototypeMap,
  ArrayPrototypeForEach,
  ArrayPrototypePush,
  FunctionPrototypeBind,
  JSONParse,
  NumberParseInt,
} = primordials;

require('internal/dns/compat');
const {
  codes: {
    ERR_INVALID_ARG_TYPE,
    ERR_INVALID_ARG_VALUE,
    ERR_INVALID_IP_ADDRESS,
  },
} = require('internal/errors');
const {
  validateArray,
  validateString,
} = require('internal/validators');
const { isIP } = require('internal/net');
const {
  DNSWrap,
  GETDNS_TRANSPORT_UDP,
  GETDNS_TRANSPORT_TCP,
  GETDNS_TRANSPORT_TLS,
} = internalBinding('dns');

const TRANSPORTS = {
  TLS: GETDNS_TRANSPORT_TLS,
  UDP: GETDNS_TRANSPORT_UDP,
  TCP: GETDNS_TRANSPORT_TCP,
};

const IPv6RE = /^\[([^[\]]*)\]/;
const addrSplitRE = /(^.+?)(?::(\d+))?$/;

class Resolver {
  constructor() {
    this._handle = new DNSWrap();
  }

  cancel() {
    this._handle.cancelAllTransactions();
  }

  getServers() {
    const data = JSONParse(this._handle.getUpstreamRecursiveServers());
    return ArrayPrototypeMap(data, (a) => {
      let address = a.address_data;
      const port = a.port || a.tls_port || '';
      if (port) {
        if (a.address_type === 'IPv6') {
          address = `[${address}]`;
        }
        address = `${address}:${port}`;
      }
      if (a.tls_auth_name) {
        return [address, a.tls_auth_name];
      }
      return address;
    });
  }

  setServers(servers, transports) {
    validateArray(servers, 'servers');

    let allAreTLS = true;
    let someAreTLS = false;

    const newSet = [];

    ArrayPrototypeForEach(servers, (ip, index) => {
      let tlsHostname;
      if (ArrayIsArray(ip)) {
        validateString(ip[0], `servers[${index}][0]`);
        validateString(ip[1], `servers[${index}][1]`);
        tlsHostname = ip[1];
        ip = ip[0];
      } else {
        validateString(ip, `servers[${index}]`);
      }
      if (tlsHostname) {
        someAreTLS = true;
      } else {
        allAreTLS = false;
      }
      let port = tlsHostname ? 853 : 53;

      let ipVersion = isIP(ip);

      if (ipVersion !== 0) {
        return ArrayPrototypePush(newSet, [ip, port, tlsHostname]);
      }

      // Check for an IPv6 in brackets.
      const match = ip.match(IPv6RE);
      if (match) {
        ipVersion = isIP(match[1]);
        if (ipVersion !== 0) {
          port = NumberParseInt(ip.replace(addrSplitRE, '$2')) || port;
          return ArrayPrototypePush(newSet, [match[1], port, tlsHostname]);
        }
      }

      // addr::port
      const addrSplitMatch = ip.match(addrSplitRE);
      if (addrSplitMatch) {
        const hostIP = addrSplitMatch[1];
        port = NumberParseInt(addrSplitMatch[2]) || port;
        ipVersion = isIP(hostIP);
        if (ipVersion !== 0) {
          return ArrayPrototypePush(newSet, [hostIP, port, tlsHostname]);
        }
      }

      throw new ERR_INVALID_IP_ADDRESS(ip);
    });

    this._handle.setUpstreamRecursiveServers(newSet);
    if (transports) {
      this._handle.setDNSTransportList(
        ArrayPrototypeMap(transports, (t, i) => {
          validateString(t, `transports[${i}]`);
          if (!TRANSPORTS[t]) {
            throw new ERR_INVALID_ARG_TYPE(t, 'DNS transport', `transports[${i}]`);
          }
          return TRANSPORTS[t];
        }));
    } else if (allAreTLS) {
      this._handle.setDNSTransportList([
        GETDNS_TRANSPORT_TLS,
      ]);
    } else if (someAreTLS) {
      this._handle.setDNSTransportList([
        GETDNS_TRANSPORT_TLS,
        GETDNS_TRANSPORT_UDP,
        GETDNS_TRANSPORT_TCP,
      ]);
    } else {
      this._handle.setDNSTransportList([
        GETDNS_TRANSPORT_UDP,
        GETDNS_TRANSPORT_TCP,
      ]);
    }
  }

  setLocalAddress(ipv4, ipv6) {
    validateString(ipv4, 'ipv4');

    if (typeof ipv6 !== 'string' && ipv6 !== undefined) {
      throw new ERR_INVALID_ARG_TYPE('ipv6', ['String', 'undefined'], ipv6);
    }
  }
}

let defaultResolver = new Resolver();
const resolverKeys = [
  'getServers',
  'resolve',
  'resolve4',
  'resolve6',
  'resolveAny',
  'resolveCaa',
  'resolveCname',
  'resolveMx',
  'resolveNaptr',
  'resolveNs',
  'resolvePtr',
  'resolveSoa',
  'resolveSrv',
  'resolveTxt',
  'reverse',
];

function getDefaultResolver() {
  return defaultResolver;
}

function setDefaultResolver(resolver) {
  defaultResolver = resolver;
}

function bindDefaultResolver(target, source) {
  ArrayPrototypeForEach(resolverKeys, (key) => {
    target[key] = FunctionPrototypeBind(source[key], defaultResolver);
  });
}

const AI_ADDRCONFIG = 1 << 0;
const AI_ALL = 1 << 1;
const AI_V4MAPPED = 1 << 2;
function validateHints(hints) {
  if ((hints & ~(AI_ADDRCONFIG | AI_ALL | AI_V4MAPPED)) !== 0) {
    throw new ERR_INVALID_ARG_VALUE('hints', hints);
  }
}

let invalidHostnameWarningEmitted = false;

function emitInvalidHostnameWarning(hostname) {
  if (invalidHostnameWarningEmitted) {
    return;
  }
  invalidHostnameWarningEmitted = true;
  process.emitWarning(
    `The provided hostname "${hostname}" is not a valid ` +
    'hostname, and is supported in the dns module solely for compatibility.',
    'DeprecationWarning',
    'DEP0118'
  );
}

module.exports = {
  bindDefaultResolver,
  getDefaultResolver,
  setDefaultResolver,
  validateHints,
  Resolver,
  emitInvalidHostnameWarning,
  AI_ADDRCONFIG,
  AI_ALL,
  AI_V4MAPPED,
};
