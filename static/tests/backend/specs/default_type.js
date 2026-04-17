'use strict';

const assert = require('assert').strict;
const {validSettings} = require('../../../..').exportedForTestingOnly;

const baseSettings = () => ({
  client_id: 'cid',
  client_secret: 'secret',
  base_url: 'https://example.test/',
});

describe(__filename, function () {
  it('still accepts a string default on user_properties', function () {
    const s = {
      ...baseSettings(),
      user_properties: {displayname: {claim: 'name', default: 'Anon'}},
    };
    assert(validSettings(s),
        `expected valid settings, got errors: ${JSON.stringify(validSettings.errors)}`);
  });

  it('accepts a boolean default on user_properties (regression for #100)', function () {
    const s = {
      ...baseSettings(),
      user_properties: {
        is_admin: {claim: 'etherpad_is_admin', default: false},
        readOnly: {default: false},
        canCreate: {default: true},
      },
    };
    assert(validSettings(s),
        `expected boolean defaults to validate, got errors: ` +
        `${JSON.stringify(validSettings.errors)}`);
  });

  it('accepts a numeric default on user_properties', function () {
    const s = {
      ...baseSettings(),
      user_properties: {quota: {default: 100}},
    };
    assert(validSettings(s),
        `expected numeric defaults to validate, got errors: ` +
        `${JSON.stringify(validSettings.errors)}`);
  });
});
