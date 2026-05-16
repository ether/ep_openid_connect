'use strict';

// End-to-end coverage for the token_endpoint_auth_method auto-pick: spin up a
// dedicated OIDC provider whose discovery doc advertises only one auth method,
// load the plugin without an explicit override, and confirm a real login flow
// succeeds — i.e. the plugin chose the advertised method.

const OidcProvider = require('../oidc-provider');
const assert = require('assert').strict;
const common = require('ep_etherpad-lite/tests/backend/common');
const epOpenidConnect = require('../../../../index');
const login = require('../login');
const plugins = require('ep_etherpad-lite/static/js/pluginfw/plugin_defs');
const settings = require('ep_etherpad-lite/node/utils/Settings');
const supertest = require('supertest');

describe(__filename, function () {
  let agent;
  let provider;
  const backup = {};
  const client = {
    client_id: 'the_client_id',
    client_secret: 'the_client_secret',
  };
  const basePluginSettings = {
    ...client,
    scope: ['openid', 'etherpad'],
    user_properties: {
      is_admin: {claim: 'etherpad_is_admin'},
      readOnly: {claim: 'etherpad_readOnly'},
      canCreate: {claim: 'etherpad_canCreate'},
    },
  };

  before(async function () {
    await common.init();
    if (!plugins.hooks.clientVars) plugins.hooks.clientVars = [];
    backup.hooks = {clientVars: plugins.hooks.clientVars};
    backup.settings = {
      requireAuthentication: settings.requireAuthentication,
      requireAuthorization: settings.requireAuthorization,
      users: settings.users,
    };
  });

  beforeEach(function () {
    agent = supertest.agent('');
    settings.requireAuthentication = true;
    settings.requireAuthorization = false;
    settings.users = {};
  });

  afterEach(async function () {
    if (provider != null) await provider.stop();
    provider = null;
    Object.assign(plugins.hooks, backup.hooks);
    settings.requireAuthentication = backup.settings.requireAuthentication;
    settings.requireAuthorization = backup.settings.requireAuthorization;
    settings.users = backup.settings.users;
  });

  // Restart `provider` with the given allowed auth methods, then load the
  // plugin pointed at it with NO explicit token_endpoint_auth_method (so the
  // picker runs).
  const startProvider = async (allowedAuthMethods) => {
    const redirectUri = new URL('/ep_openid_connect/callback', common.baseUrl).href;
    provider = new OidcProvider();
    await provider.start({
      // oidc-provider v9: the global allow-list drives the advertised
      // token_endpoint_auth_methods_supported and is enforced at the token
      // endpoint. Each client must also declare which method it uses.
      clientAuthMethods: allowedAuthMethods,
      clients: [{
        ...client,
        redirect_uris: [redirectUri],
        token_endpoint_auth_method: allowedAuthMethods[0],
      }],
    });
    await epOpenidConnect.loadSettings('loadSettings', {settings: {ep_openid_connect: {
      ...basePluginSettings,
      base_url: common.baseUrl,
      issuer: provider.issuer,
      // Deliberately omit token_endpoint_auth_method — that's what we're testing.
    }}});
  };

  it('picks client_secret_post when only that is advertised', async function () {
    await startProvider(['client_secret_post']);
    const url = new URL(`/p/${common.randomString()}`, common.baseUrl).toString();
    const res = await login(agent, provider.issuer, url, 'normalUser');
    assert.equal(res.request.url, url,
        `expected redirect back to ${url}, got ${res.request.url}`);
    assert.equal(res.status, 200);
  });

  it('picks client_secret_basic when only that is advertised', async function () {
    await startProvider(['client_secret_basic']);
    const url = new URL(`/p/${common.randomString()}`, common.baseUrl).toString();
    const res = await login(agent, provider.issuer, url, 'normalUser');
    assert.equal(res.request.url, url,
        `expected redirect back to ${url}, got ${res.request.url}`);
    assert.equal(res.status, 200);
  });

  it('prefers client_secret_post when both are advertised', async function () {
    // When both methods are on offer the plugin must pick _post (matches the
    // openid-client@6 default and is the one GitLab.com actually accepts at
    // the token endpoint). The test client is registered as _post-only, so a
    // _basic attempt would 401 at the token endpoint.
    await startProvider(['client_secret_post', 'client_secret_basic']);
    const url = new URL(`/p/${common.randomString()}`, common.baseUrl).toString();
    const res = await login(agent, provider.issuer, url, 'normalUser');
    assert.equal(res.request.url, url,
        `expected redirect back to ${url}, got ${res.request.url}`);
    assert.equal(res.status, 200);
  });
});
