'use strict';

const assert = require('assert').strict;
const {pickAuthMethod} = require('../../../..').exportedForTestingOnly;

describe(__filename, function () {
  describe('with no override', function () {
    it('prefers client_secret_post when advertised', function () {
      assert.equal(
          pickAuthMethod(['client_secret_basic', 'client_secret_post']),
          'client_secret_post');
    });

    it('uses client_secret_basic when only that is advertised', function () {
      assert.equal(pickAuthMethod(['client_secret_basic']), 'client_secret_basic');
    });

    it('uses client_secret_post when only that is advertised', function () {
      assert.equal(pickAuthMethod(['client_secret_post']), 'client_secret_post');
    });

    it('ignores unsupported methods', function () {
      // None of these are methods this plugin can implement, so the picker
      // must fall back rather than pretend to support them.
      assert.equal(
          pickAuthMethod(['private_key_jwt', 'client_secret_jwt', 'none']),
          'client_secret_basic');
    });

    it('prefers client_secret_post even when other methods are advertised first', function () {
      assert.equal(
          pickAuthMethod(['private_key_jwt', 'client_secret_post', 'client_secret_basic']),
          'client_secret_post');
    });

    it('falls back to client_secret_basic when supported is undefined', function () {
      // RFC 8414 §2: absence of token_endpoint_auth_methods_supported defaults
      // to client_secret_basic.
      assert.equal(pickAuthMethod(undefined), 'client_secret_basic');
    });

    it('falls back to client_secret_basic when supported is empty', function () {
      assert.equal(pickAuthMethod([]), 'client_secret_basic');
    });

    it('falls back to client_secret_basic when supported is not an array', function () {
      assert.equal(pickAuthMethod('client_secret_post'), 'client_secret_basic');
      assert.equal(pickAuthMethod(null), 'client_secret_basic');
    });
  });

  describe('with override', function () {
    it('honours an explicit client_secret_basic override', function () {
      assert.equal(
          pickAuthMethod(['client_secret_post'], 'client_secret_basic'),
          'client_secret_basic');
    });

    it('honours an explicit client_secret_post override', function () {
      assert.equal(
          pickAuthMethod(['client_secret_basic'], 'client_secret_post'),
          'client_secret_post');
    });

    it('honours override even when supported list is missing', function () {
      assert.equal(
          pickAuthMethod(undefined, 'client_secret_post'),
          'client_secret_post');
    });
  });
});
