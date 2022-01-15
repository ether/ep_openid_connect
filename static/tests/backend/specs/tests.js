'use strict';

const OidcClient = require('../oidc-client');
const OidcProvider = require('../oidc-provider');
const assert = require('assert').strict;
const common = require('ep_etherpad-lite/tests/backend/common');
const epOpenidConnect = require('../../../../index');
const login = require('../login');
const padManager = require('ep_etherpad-lite/node/db/PadManager');
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
    backup.settings = {...settings};
    settings.requireAuthentication = true;
    settings.requireAuthorization = false;
    provider = new OidcProvider();
    const clients =
        [{...client, redirect_uris: [new URL('/ep_openid_connect/callback', common.baseUrl)]}];
    await provider.start({clients});
    issuer = provider.issuer;
    pluginSettings.base_url = common.baseUrl;
    pluginSettings.issuer = issuer;
    await epOpenidConnect.loadSettings(
        'loadSettings', {settings: {ep_openid_connect: pluginSettings}});
  });

  beforeEach(async function () {
    agent = supertest.agent('');
  });

  afterEach(async function () {
    if (socket != null) socket.close();
    socket = null;
  });

  after(async function () {
    if (provider != null) await provider.stop();
    provider = null;
    Object.assign(settings, backup.settings);
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
        .expect('www-authenticate', /^Bearer /);
  });

  it('Authorization header results in 401 instead of redirect', async function () {
    await agent.get(common.baseUrl)
        .set('Authorization', 'Basic dXNlcm5hbWU6cGFzc3dvcmQ=')
        .expect(401)
        .expect('www-authenticate', /^Bearer /);
  });

  describe('Bearer token authentication', function () {
    let client;

    before(async function () {
      client = new OidcClient();
      await client.start(issuer);
    });

    after(async function () {
      if (client != null) await client.stop();
      client = null;
    });

    it('valid token', async function () {
      const {tokenset: {access_token}} =
          await client.authenticate(pluginSettings.scope.join(' '), 'normalUser');
      await agent.get(new URL('/', common.baseUrl))
          .set('Authorization', `Bearer ${access_token}`)
          .expect(200);
    });

    it('claims apply', async function () {
      const {tokenset: {access_token}} =
          await client.authenticate(pluginSettings.scope.join(' '), 'adminUser');
      await agent.get(new URL('/admin/', common.baseUrl))
          .set('Authorization', `Bearer ${access_token}`)
          .expect(200);
    });

    it('missing token', async function () {
      await agent.get(new URL('/', common.baseUrl))
          .set('Authorization', 'Bearer ')
          .expect(401)
          .expect('WWW-Authenticate', /^Bearer.* error="invalid_request"/);
    });

    it('bad token value', async function () {
      await agent.get(new URL('/', common.baseUrl))
          .set('Authorization', 'Bearer foobarbaz')
          .expect(401)
          .expect('WWW-Authenticate', /^Bearer.* error="invalid_token"/);
    });

    it('expired token', async function () {
      const {tokenset: {access_token}} =
          await client.authenticate(pluginSettings.scope.join(' '), 'normalUser');
      // OidcProvider is configured with 5s access token lifetime. Wait a bit over a second in case
      // the expiration logic uses integer math with seconds instead of milliseconds.
      await new Promise((resolve) => setTimeout(resolve, 6100));
      await agent.get(new URL('/', common.baseUrl))
          .set('Authorization', `Bearer ${access_token}`)
          .expect(401)
          .expect('WWW-Authenticate', /^Bearer.* error="invalid_token"/);
    });

    it('revoked token', async function () {
      const {tokenset: {access_token}} =
          await client.authenticate(pluginSettings.scope.join(' '), 'normalUser');
      await client.revokeToken(access_token, 'access_token');
      await agent.get(new URL('/', common.baseUrl))
          .set('Authorization', `Bearer ${access_token}`)
          .expect(401)
          .expect('WWW-Authenticate', /^Bearer.* error="invalid_token"/);
    });

    it('wrong token type (refresh token)', async function () {
      const {tokenset: {refresh_token}} =
          await client.authenticate(pluginSettings.scope.join(' '), 'normalUser');
      await agent.get(new URL('/', common.baseUrl))
          .set('Authorization', `Bearer ${refresh_token}`)
          .expect(401)
          .expect('WWW-Authenticate', /^Bearer.* error="invalid_token"/);
    });

    it('wrong token type (ID token)', async function () {
      const {tokenset: {id_token}} =
          await client.authenticate(pluginSettings.scope.join(' '), 'normalUser');
      await agent.get(new URL('/', common.baseUrl))
          .set('Authorization', `Bearer ${id_token}`)
          .expect(401)
          .expect('WWW-Authenticate', /^Bearer.* error="invalid_token"/);
    });

    it('insufficient scope', async function () {
      const {tokenset: {access_token}} = await client.authenticate('openid', 'normalUser');
      await agent.get(new URL('/', common.baseUrl))
          .set('Authorization', `Bearer ${access_token}`)
          .expect(401)
          .expect('WWW-Authenticate', /^Bearer.* error="insufficient_scope"/);
    });
  });
});
