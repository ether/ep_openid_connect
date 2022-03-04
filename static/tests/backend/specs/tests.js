'use strict';

const OidcProvider = require('../oidc-provider');
const assert = require('assert').strict;
const common = require('ep_etherpad-lite/tests/backend/common');
const epOpenidConnect = require('../../../../index');
const login = require('../login');
const padManager = require('ep_etherpad-lite/node/db/PadManager');
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
  const pluginSettings = {
    ...epOpenidConnect.exportedForTestingOnly.defaultSettings,
    ...client,
    // base_url and issuer will be filled in later.
    scope: ['openid', 'etherpad'],
    user_properties: {
      is_admin: {claim: 'etherpad_is_admin'},
      readOnly: {claim: 'etherpad_readOnly'},
      canCreate: {claim: 'etherpad_canCreate'},
    },
  };
  let socket;

  before(async function () {
    await common.init();
    if (!plugins.hooks.clientVars) plugins.hooks.clientVars = [];
    backup.hooks = {clientVars: plugins.hooks.clientVars};
    backup.settings = {...settings};
    provider = new OidcProvider();
    const clients =
        [{...client, redirect_uris: [new URL('/ep_openid_connect/callback', common.baseUrl)]}];
    await provider.start({clients});
  });

  beforeEach(async function () {
    agent = supertest.agent('');
    issuer = provider.issuer;
    pluginSettings.base_url = common.baseUrl;
    pluginSettings.issuer = issuer;
    settings.requireAuthentication = true;
    settings.requireAuthorization = false;
    settings.users = {};
    await epOpenidConnect.loadSettings(
        'loadSettings', {settings: {ep_openid_connect: pluginSettings}});
  });

  afterEach(async function () {
    if (socket != null) socket.close();
    socket = null;
    Object.assign(plugins.hooks, backup.hooks);
    Object.assign(settings, backup.settings);
  });

  after(async function () {
    if (provider != null) await provider.stop();
    provider = null;
  });

  it('not logged in redirects to login endpoint', async function () {
    await agent.get(common.baseUrl)
        .expect(303)
        .expect('location', new URL('/ep_openid_connect/login', common.baseUrl).toString());
  });

  it('login endpoint redirects to authorization URL', async function () {
    await agent.get(new URL('/ep_openid_connect/login', common.baseUrl))
        .expect(303)
        .expect('location', /.*/)
        .expect((res) => {
          assert(res.headers.location.startsWith(`${new URL('/auth', issuer)}?`));
          const location = new URL(res.headers.location);
          const params = location.searchParams;
          assert.deepEqual(params.getAll('redirect_uri'),
              [new URL('/ep_openid_connect/callback', common.baseUrl).toString()]);
          assert.deepEqual(params.getAll('client_id'), [pluginSettings.client_id]);
          assert.deepEqual(params.getAll('response_type'), ['code']);
          assert.deepEqual(params.getAll('scope'), [pluginSettings.scope.join(' ')]);
          for (const param of ['code_challenge', 'nonce', 'state']) {
            assert.equal(params.getAll(param).length, 1);
            assert.notEqual(params.get(param), '');
          }
        });
  });

  it('normalUser can create and edit a pad', async function () {
    const padId = common.randomString();
    const url = new URL(`/p/${padId}`, common.baseUrl).toString();
    const res = await login(agent, issuer, url, 'normalUser');
    assert.equal(res.request.url, url); // Should have been redirected back after authenticating.
    assert.equal(res.status, 200);
    socket = await common.connect(res);
    const msg = await common.handshake(socket, padId);
    assert.equal(msg.type, 'CLIENT_VARS', `not a CLIENT_VARS message: ${JSON.stringify(msg)}`);
    assert.equal(msg.data.readonly, false);
  });

  it('noCreate user is unable to create a pad', async function () {
    const padId = common.randomString();
    const url = new URL(`/p/${padId}`, common.baseUrl).toString();
    const res = await login(agent, issuer, url, 'noCreate');
    assert.equal(res.request.url, url); // Should have been redirected back after authenticating.
    assert.equal(res.status, 200);
    socket = await common.connect(res);
    const message = await common.handshake(socket, padId);
    assert.equal(message.accessStatus, 'deny');
  });

  it('noCreate user can edit an existing pad', async function () {
    const padId = common.randomString();
    await padManager.getPad(padId, 'this is a test');
    assert(await padManager.doesPadExist(padId));
    const url = new URL(`/p/${padId}`, common.baseUrl).toString();
    const res = await login(agent, issuer, url, 'noCreate');
    assert.equal(res.request.url, url); // Should have been redirected back after authenticating.
    assert.equal(res.status, 200);
    socket = await common.connect(res);
    const msg = await common.handshake(socket, padId);
    assert.equal(msg.type, 'CLIENT_VARS', `not a CLIENT_VARS message: ${JSON.stringify(msg)}`);
    assert.equal(msg.data.readonly, false);
  });

  it('readOnly user is unable to create a pad', async function () {
    const padId = common.randomString();
    const url = new URL(`/p/${padId}`, common.baseUrl).toString();
    const res = await login(agent, issuer, url, 'readOnly');
    assert.equal(res.request.url, url); // Should have been redirected back after authenticating.
    assert.equal(res.status, 200);
    socket = await common.connect(res);
    const message = await common.handshake(socket, padId);
    assert.equal(message.accessStatus, 'deny');
  });

  it('readOnly user can view but not edit an existing pad', async function () {
    const padId = common.randomString();
    await padManager.getPad(padId, 'this is a test');
    assert(await padManager.doesPadExist(padId));
    const url = new URL(`/p/${padId}`, common.baseUrl).toString();
    const res = await login(agent, issuer, url, 'readOnly');
    assert.equal(res.request.url, url); // Should have been redirected back after authenticating.
    assert.equal(res.status, 200);
    socket = await common.connect(res);
    const msg = await common.handshake(socket, padId);
    assert.equal(msg.type, 'CLIENT_VARS', `not a CLIENT_VARS message: ${JSON.stringify(msg)}`);
    assert.equal(msg.data.readonly, true);
  });

  it('authentication failure', async function () {
    const res = await login(agent, issuer, new URL('/', common.baseUrl).toString(), 'fail');
    assert.equal(res.status, 500);
    const gotUrl = res.request.url;
    const wantUrlBase = new URL('/ep_openid_connect/callback?', common.baseUrl).toString();
    assert(gotUrl.startsWith(wantUrlBase), `expected ${gotUrl} to start with ${wantUrlBase}`);
  });

  describe('prohibited usernames', function () {
    // The OIDC provider rejects '' as a username so that can't be tested here.
    for (const username of [...pluginSettings.prohibited_usernames, '__proto__']) {
      it(JSON.stringify(username), async function () {
        const res = await login(agent, issuer, new URL('/', common.baseUrl).toString(), username);
        assert(res.request.url.startsWith(new URL('/ep_openid_connect/callback?', common.baseUrl)));
        assert.equal(res.status, 500);
      });
    }
  });

  describe('admin access', function () {
    it('adminUser can access /admin/', async function () {
      const url = new URL('/admin/', common.baseUrl).toString();
      // Note that the username is "adminUser", not "admin", because "admin" is prohibited.
      const res = await login(agent, issuer, url, 'adminUser');
      assert.equal(res.request.url, url); // Should have been redirected back after authenticating.
      assert.equal(res.status, 200);
    });

    it('normalUser is unable to access /admin/', async function () {
      const url = new URL('/admin/', common.baseUrl).toString();
      const res = await login(agent, issuer, url, 'normalUser');
      assert.equal(res.request.url, url); // Should have been redirected back after authenticating.
      assert.equal(res.status, 403);
    });
  });

  it('visiting callback endpoint without session does not crash', async function () {
    await agent.get(new URL('/ep_openid_connect/callback', common.baseUrl))
        .expect(500);
  });

  it('visiting login endpoint directly redirects to base URL', async function () {
    const url = new URL('/ep_openid_connect/login', common.baseUrl).toString();
    const res = await login(agent, issuer, url, 'normalUser');
    assert.equal(res.request.url, new URL('/', common.baseUrl).toString());
    assert.equal(res.status, 200);
  });

  it('visiting logout endpoint destroys session, redirects to base URL', async function () {
    const padId = common.randomString();
    const url = new URL(`/p/${padId}`, common.baseUrl).toString();
    const res = await login(agent, issuer, url, 'normalUser');
    assert.equal(res.request.url, url);
    assert.equal(res.status, 200);
    await agent.get(new URL('/ep_openid_connect/logout', common.baseUrl))
        .expect(303)
        .expect('location', new URL('/', common.baseUrl).toString());
    // Visiting any page that requires authentication should now redirect to the login page.
    await agent.get(new URL('/', common.baseUrl))
        .expect(303)
        .expect('location', new URL('/ep_openid_connect/login', common.baseUrl).toString());
  });

  it('HTTP PUT gives 401 instead of redirect', async function () {
    await agent.put(common.baseUrl)
        .expect(401)
        .expect('www-authenticate', 'Etherpad');
  });

  it('Authorization header results in 401 instead of redirect', async function () {
    await agent.get(common.baseUrl)
        .set('Authorization', 'Basic dXNlcm5hbWU6cGFzc3dvcmQ=')
        .expect(401)
        .expect('www-authenticate', 'Etherpad');
  });

  describe('user_properties', function () {
    it('uses existing settings.users[username] object', async function () {
      const wantUser = {foo: 'bar'};
      settings.users.normalUser = wantUser;
      const padId = common.randomString();
      const url = new URL(`/p/${padId}`, common.baseUrl).toString();
      const res = await login(agent, issuer, url, 'normalUser');
      assert.equal(res.request.url, url);
      assert.equal(res.status, 200);
      socket = await common.connect(res);
      const gotUserP = new Promise((resolve) => {
        plugins.hooks.clientVars =
            [{hook_fn: (hn, ctx) => resolve(ctx.socket.client.request.session.user)}];
      });
      const msg = await common.handshake(socket, padId);
      assert.equal(msg.type, 'CLIENT_VARS', `not a CLIENT_VARS message: ${JSON.stringify(msg)}`);
      assert.equal(settings.users.normalUser, wantUser);
      assert.equal(settings.users.normalUser.foo, 'bar');
      // They won't be reference equal because each request loads the user object from the session
      // store.
      assert.deepEqual(await gotUserP, settings.users.normalUser);
    });

    it('sets settings.users[username] to new object if missing', async function () {
      assert(settings.users.normalUser == null);
      const padId = common.randomString();
      const url = new URL(`/p/${padId}`, common.baseUrl).toString();
      const res = await login(agent, issuer, url, 'normalUser');
      assert.equal(res.request.url, url);
      assert.equal(res.status, 200);
      socket = await common.connect(res);
      const gotUserP = new Promise((resolve) => {
        plugins.hooks.clientVars =
            [{hook_fn: (hn, ctx) => resolve(ctx.socket.client.request.session.user)}];
      });
      const msg = await common.handshake(socket, padId);
      assert.equal(msg.type, 'CLIENT_VARS', `not a CLIENT_VARS message: ${JSON.stringify(msg)}`);
      assert(settings.users.normalUser != null);
      // They won't be reference equal because each request loads the user object from the session
      // store.
      assert.deepEqual(await gotUserP, settings.users.normalUser);
    });

    it('displayname defaults to name claim', async function () {
      assert(settings.users.normalUser == null);
      const padId = common.randomString();
      const url = new URL(`/p/${padId}`, common.baseUrl).toString();
      const res = await login(agent, issuer, url, 'normalUser');
      assert.equal(res.request.url, url);
      assert.equal(res.status, 200);
      assert.equal(settings.users.normalUser.displayname, 'Firstname Lastname');
    });

    it('setting empty displayname descriptor cancels default behavior', async function () {
      assert(settings.users.normalUser == null);
      await epOpenidConnect.loadSettings('loadSettings', {settings: {ep_openid_connect: {
        ...pluginSettings,
        user_properties: {displayname: {}},
      }}});
      const padId = common.randomString();
      const url = new URL(`/p/${padId}`, common.baseUrl).toString();
      const res = await login(agent, issuer, url, 'normalUser');
      assert.equal(res.request.url, url);
      assert.equal(res.status, 200);
      assert(!('displayname' in settings.users.normalUser));
    });

    it('username is set to sub claim', async function () {
      assert(settings.users.normalUser == null);
      const padId = common.randomString();
      const url = new URL(`/p/${padId}`, common.baseUrl).toString();
      const res = await login(agent, issuer, url, 'normalUser');
      assert.equal(res.request.url, url);
      assert.equal(res.status, 200);
      assert.equal(settings.users.normalUser.username, 'normalUser');
    });

    describe('username can\'t be changed', function () {
      for (const dsc of [
        null,
        {},
        {default: 'something else'},
        {claim: 'preferred_username'},
        {claim: 'preferred_username', default: 'something else'},
      ]) {
        it(`descriptor: ${JSON.stringify(dsc)}`, async function () {
          await epOpenidConnect.loadSettings('loadSettings', {settings: {ep_openid_connect: {
            ...pluginSettings,
            user_properties: {username: dsc},
          }}});
          // Settings validation should fail, resulting in an unconfigured state and causing
          // Etherpad to fall back to built-in authn.
          const res = await agent.get(new URL('/ep_openid_connect/login', common.baseUrl));
          assert.equal(res.status, 401);
        });
      }
    });

    describe('{settings.json, claim value, user_properties} combinations', function () {
      const testCases = [];
      for (const user of [{}, {prop: undefined}, {prop: null}, {prop: 'userValue'}]) {
        for (const claimValue of [undefined, null, 'claimValue']) {
          for (const cfg of [
            {},
            {prop: null},
            {prop: {}},
            {prop: {default: 'defaultValue'}},
            {prop: {claim: 'prop'}},
            {prop: {claim: 'prop', default: 'defaultValue'}},
          ]) {
            const p = cfg.prop || {};
            const wantIn = !!(
              p.default ||
              (p.claim && claimValue !== undefined) ||
              ('prop' in user && cfg.prop !== null)); // eslint-disable-line eqeqeq
            const wantValue =
                p.claim && claimValue !== undefined ? claimValue
                : 'prop' in user ? user.prop
                : p.default ? p.default
                : undefined;
            const desc =
                `user.prop=${'prop' in user ? user.prop : '<unset>'}, ` +
                `claimValue=${claimValue === undefined ? '<unset>' : claimValue}, ` +
                `user_properties.prop=${'prop' in cfg ? JSON.stringify(cfg.prop) : '<unset>'} -> ` +
                `${wantIn ? wantValue : '<unset>'}`;
            testCases.push({desc, user, claimValue, cfg, wantIn, wantValue});
          }
        }
      }

      for (const {desc, user, claimValue, cfg, wantIn, wantValue} of testCases) {
        it(desc, async function () {
          const username =
              claimValue === undefined ? 'claimUnset'
              : claimValue != null ? 'claimVal'
              : 'claimNull';
          settings.users[username] = {...user};
          await epOpenidConnect.loadSettings('loadSettings', {settings: {ep_openid_connect: {
            ...pluginSettings,
            user_properties: cfg,
          }}});
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
          assert.equal(
              msg.type, 'CLIENT_VARS', `not a CLIENT_VARS message: ${JSON.stringify(msg)}`);
          const gotUser = await userP;
          assert.equal('prop' in gotUser, wantIn);
          if (wantIn) assert.equal(gotUser.prop, wantValue);
        });
      }
    });
  });
});
