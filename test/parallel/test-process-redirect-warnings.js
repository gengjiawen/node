'use strict';

// Tests the --redirect-warnings command line flag by spawning
// a new child node process that emits a warning into a temporary
// warnings file. Once the process completes, the warning file is
// opened and the contents are validated

const common = require('../common');
const fixtures = require('../common/fixtures');
const fs = require('fs');
const fork = require('child_process').fork;
const path = require('path');
const assert = require('assert');

const tmpdir = require('../common/tmpdir');
tmpdir.refresh();

const warnmod = fixtures.path('warnings.js');
const warnpath = path.join(tmpdir.path, 'warnings.txt');

fork(warnmod, { execArgv: [`--redirect-warnings=${warnpath}`] }).on(
  'exit',
  common.mustCall(() => {
    fs.readFile(
      warnpath,
      'utf8',
      common.mustCall((err, data) => {
        assert.ifError(err);
        assert(/\(node:\d+\) Warning: a bad practice warning/.test(data));
      })
    );
  })
);
