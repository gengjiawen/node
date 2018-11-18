'use strict';

const common = require('../common');
const assert = require('assert');

const b = Buffer.allocUnsafe(1024);
const c = Buffer.allocUnsafe(512);

const errorProperty = {
  code: 'ERR_OUT_OF_RANGE',
  type: RangeError,
  message: 'Index out of range'
};

let cntr = 0;

{
  // copy 512 bytes, from 0 to 512.
  b.fill(++cntr);
  c.fill(++cntr);
  const copied = b.copy(c, 0, 0, 512);
  assert.strictEqual(copied, 512);
  for (let i = 0; i < c.length; i++) {
    assert.strictEqual(c[i], b[i]);
  }
}

{
  // copy c into b, without specifying sourceEnd
  b.fill(++cntr);
  c.fill(++cntr);
  const copied = c.copy(b, 0, 0);
  assert.strictEqual(copied, c.length);
  for (let i = 0; i < c.length; i++) {
    assert.strictEqual(b[i], c[i]);
  }
}

{
  // copy c into b, without specifying sourceStart
  b.fill(++cntr);
  c.fill(++cntr);
  const copied = c.copy(b, 0);
  assert.strictEqual(copied, c.length);
  for (let i = 0; i < c.length; i++) {
    assert.strictEqual(b[i], c[i]);
  }
}

{
  // copy longer buffer b to shorter c without targetStart
  b.fill(++cntr);
  c.fill(++cntr);
  const copied = b.copy(c);
  assert.strictEqual(copied, c.length);
  for (let i = 0; i < c.length; i++) {
    assert.strictEqual(c[i], b[i]);
  }
}

{
  // copy starting near end of b to c
  b.fill(++cntr);
  c.fill(++cntr);
  const copied = b.copy(c, 0, b.length - Math.floor(c.length / 2));
  assert.strictEqual(copied, Math.floor(c.length / 2));
  for (let i = 0; i < Math.floor(c.length / 2); i++) {
    assert.strictEqual(c[i], b[b.length - Math.floor(c.length / 2) + i]);
  }
  for (let i = Math.floor(c.length / 2) + 1; i < c.length; i++) {
    assert.strictEqual(c[c.length - 1], c[i]);
  }
}

{
  // try to copy 513 bytes, and check we don't overrun c
  b.fill(++cntr);
  c.fill(++cntr);
  const copied = b.copy(c, 0, 0, 513);
  assert.strictEqual(copied, c.length);
  for (let i = 0; i < c.length; i++) {
    assert.strictEqual(c[i], b[i]);
  }
}

{
  // copy 768 bytes from b into b
  b.fill(++cntr);
  b.fill(++cntr, 256);
  const copied = b.copy(b, 0, 256, 1024);
  assert.strictEqual(copied, 768);
  for (let i = 0; i < b.length; i++) {
    assert.strictEqual(b[i], cntr);
  }
}

// copy string longer than buffer length (failure will segfault)
const bb = Buffer.allocUnsafe(10);
bb.fill('hello crazy world');

// Try to copy from before the beginning of b. Should not throw.
b.copy(c, 0, 100, 10);

// copy throws at negative sourceStart
common.expectsError(
  () => Buffer.allocUnsafe(5).copy(Buffer.allocUnsafe(5), 0, -1),
  errorProperty
);

{
  // check sourceEnd resets to targetEnd if former is greater than the latter
  b.fill(++cntr);
  c.fill(++cntr);
  b.copy(c, 0, 0, 1025);
  for (let i = 0; i < c.length; i++) {
    assert.strictEqual(c[i], b[i]);
  }
}

// throw with negative sourceEnd
common.expectsError(() => b.copy(c, 0, -1), errorProperty);

// when sourceStart is greater than sourceEnd, zero copied
assert.strictEqual(b.copy(c, 0, 100, 10), 0);

// when targetStart > targetLength, zero copied
assert.strictEqual(b.copy(c, 512, 0, 10), 0);

// Test that the `target` can be a Uint8Array.
{
  const d = new Uint8Array(c);
  // copy 512 bytes, from 0 to 512.
  b.fill(++cntr);
  d.fill(++cntr);
  const copied = b.copy(d, 0, 0, 512);
  assert.strictEqual(copied, 512);
  for (let i = 0; i < d.length; i++) {
    assert.strictEqual(d[i], b[i]);
  }
}

// Test that the source can be a Uint8Array, too.
{
  const e = new Uint8Array(b);
  // copy 512 bytes, from 0 to 512.
  e.fill(++cntr);
  c.fill(++cntr);
  const copied = Buffer.prototype.copy.call(e, c, 0, 0, 512);
  assert.strictEqual(copied, 512);
  for (let i = 0; i < c.length; i++) {
    assert.strictEqual(c[i], e[i]);
  }
}
