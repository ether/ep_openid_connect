'use strict';

// Coverage for `user_properties.<name>.role`: when the named role string is
// present in the userinfo's `roles` array, the property is set to boolean
// `true`. Useful for IdPs (Azure/Entra ID, Keycloak) that publish role
// assignments through a single `roles` array claim rather than a dedicated
// claim per property.

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
  const backup = {};
  let provider;
  let issuer;
  const client = {
    client_id: 'the_client_id',
    client_secret: 'the_client_secret',
  };
  const basePluginSettings = {
    ...client,
    scope: ['openid', 'etherpad'],
  };
  let socket;

  before(async function () {
    await common.init();
    if (!plugins.hooks.clientVars) plugins.hooks.clientVars = [];
    backup.hooks = {clientVars: plugins.hooks.clientVars};
    backup.settings = {
      requireAuthentication: settings.requireAuthentication,
      requireAuthorization: settings.requireAuthorization,
      users: settings.users,
    };
    provider = new OidcProvider();
    const clients =
        [{...client, redirect_uris: [new URL('/ep_openid_connect/callback', common.baseUrl).href]}];
    await provider.start({clients});
  });

  beforeEach(async function () {
    agent = supertest.agent('');
    issuer = provider.issuer;
    settings.requireAuthentication = true;
    settings.requireAuthorization = false;
    settings.users = {};
  });

  afterEach(async function () {
    if (socket != null) socket.close();
    socket = null;
    Object.assign(plugins.hooks, backup.hooks);
    settings.requireAuthentication = backup.settings.requireAuthentication;
    settings.requireAuthorization = backup.settings.requireAuthorization;
    settings.users = backup.settings.users;
  });

  after(async function () {
    if (provider != null) await provider.stop();
    provider = null;
  });

  const loadWithUserProperties = async (user_properties) => {
    await epOpenidConnect.loadSettings('loadSettings', {settings: {ep_openid_connect: {
      ...basePluginSettings,
      base_url: common.baseUrl,
      issuer,
      user_properties,
    }}});
  };

  // Login that captures the post-handshake session.user and returns it.
  const loginAndGetUser = async (username) => {
    const padId = common.randomString();
    const url = new URL(`/p/${padId}`, common.baseUrl).toString();
    const res = await login(agent, issuer, url, username);
    assert.equal(res.request.url, url);
    assert.equal(res.status, 200);
    socket = await common.connect(res);
    const userP = new Promise((resolve) => {
      plugins.hooks.clientVars =
          [{hook_fn: (hn, ctx) => resolve(ctx.socket.client.request.session.user)}];
    });
    const msg = await common.handshake(socket, padId);
    assert.equal(msg.type, 'CLIENT_VARS', `not a CLIENT_VARS message: ${JSON.stringify(msg)}`);
    return userP;
  };

  it('sets the property to boolean true when the role is present', async function () {
    await loadWithUserProperties({is_admin: {role: 'etherpad_admin'}});
    const user = await loginAndGetUser('roleAdmin');
    assert.equal(user.is_admin, true, 'is_admin must be the boolean true, not a string');
  });

  it('leaves the property unset when the role is not in the roles array', async function () {
    await loadWithUserProperties({is_admin: {role: 'missing_role'}});
    const user = await loginAndGetUser('roleAdmin'); // has roles, just not this one
    assert(!('is_admin' in user),
        `is_admin should not be set when role is absent; got ${JSON.stringify(user.is_admin)}`);
  });

  it('leaves the property unset when roles array is empty', async function () {
    await loadWithUserProperties({is_admin: {role: 'etherpad_admin'}});
    const user = await loginAndGetUser('emptyRolesUser');
    assert(!('is_admin' in user));
  });

  it('does not crash when the roles claim is entirely missing', async function () {
    // `normalUser` doesn't have "role" in its sub, so the test account
    // synthesises no `roles` claim at all. Pre-#111 code would have thrown
    // `Cannot read properties of undefined (reading 'indexOf')`.
    await loadWithUserProperties({is_admin: {role: 'etherpad_admin'}});
    const user = await loginAndGetUser('normalUser');
    assert(!('is_admin' in user));
  });

  it('falls through to default when role is absent', async function () {
    await loadWithUserProperties({
      is_admin: {role: 'missing_role', default: false},
    });
    const user = await loginAndGetUser('roleAdmin');
    assert.equal(user.is_admin, false);
  });

  it('uses claim value in preference to role match', async function () {
    // Both `claim` and `role` set: the explicit claim wins. The test account
    // for `adminroleUser` emits `etherpad_is_admin: true` (sub contains
    // "admin") AND `roles: ['etherpad_admin', ...]`. With a `claim`
    // descriptor the role branch must not overwrite the claim's value.
    await loadWithUserProperties({
      is_admin: {claim: 'etherpad_is_admin', role: 'should_not_match'},
    });
    const user = await loginAndGetUser('adminroleUser');
    assert.equal(user.is_admin, true); // came from claim, not role fallback
  });

  it('role can grant a property whose claim is absent', async function () {
    // `claim` is checked first but only fires when the claim key is *in*
    // userinfo. If it isn't, the role branch should run.
    await loadWithUserProperties({
      is_admin: {claim: 'definitely_not_a_claim', role: 'etherpad_admin'},
    });
    const user = await loginAndGetUser('roleUser');
    assert.equal(user.is_admin, true);
  });
});
