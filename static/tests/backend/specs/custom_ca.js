'use strict';

// End-to-end coverage for the `ca` setting: stand up an HTTPS-fronted OIDC
// provider with a self-signed certificate, point the plugin at it, and
// confirm a real login completes when the matching CA is configured (and
// fails when it isn't). This is the only sound way to prove that the
// custom-fetch wiring actually replaces Node's default fetch — a unit test
// that just checks `config[customFetch]` is set would miss the case where
// undici and openid-client disagree on the option shape.

const Provider = require('oidc-provider').default;
const MemoryAdapter = require('oidc-provider/lib/adapters/memory_adapter').default;
const assert = require('assert').strict;
const child_process = require('child_process');
const common = require('ep_etherpad-lite/tests/backend/common');
const epOpenidConnect = require('../../../../index');
const fs = require('fs');
const https = require('https');
const os = require('os');
const path = require('path');
const settings = require('ep_etherpad-lite/node/utils/Settings');
const util = require('util');

// Generate a self-signed cert valid for localhost via the OpenSSL CLI.
// Using a CLI avoids pulling in `selfsigned`+`@peculiar/x509`+`node-forge`
// as devDependencies just for one test, and `openssl` is available on every
// CI runner and dev machine.
const generateSelfSignedCert = () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ep-openid-cert-'));
  const keyPath = path.join(dir, 'key.pem');
  const certPath = path.join(dir, 'cert.pem');
  child_process.execFileSync('openssl', [
    'req', '-x509',
    '-newkey', 'rsa:2048',
    '-nodes',
    '-keyout', keyPath,
    '-out', certPath,
    '-days', '1',
    '-subj', '/CN=localhost',
    '-addext', 'subjectAltName=DNS:localhost,IP:127.0.0.1',
  ], {stdio: 'pipe'});
  return {
    dir,
    key: fs.readFileSync(keyPath, 'utf8'),
    cert: fs.readFileSync(certPath, 'utf8'),
    keyPath,
    certPath,
  };
};

const httpsListen = util.promisify(https.Server.prototype.listen);
const httpsClose = util.promisify(https.Server.prototype.close);

// No-op subclass mirrors the helper in ../oidc-provider.js — silences the
// MemoryAdapter "not for production" warning.
class Adapter extends MemoryAdapter {}

// Minimal HTTPS-fronted OIDC provider for the CA-trust test. Mirrors the
// happy path of static/tests/backend/oidc-provider.js but listens on TLS.
class HttpsOidcProvider {
  async start({clients, tls}) {
    this._server = https.createServer(tls);
    await httpsListen.call(this._server, 0, 'localhost');
    this.issuer = `https://localhost:${this._server.address().port}/`;
    this._provider = new Provider(this.issuer, {
      adapter: Adapter,
      claims: {etherpad: ['name']},
      clients,
      cookies: {keys: [common.randomString()]},
      features: {devInteractions: {enabled: false}},
      findAccount: async (ctx, sub) => ({
        accountId: sub,
        claims: async () => ({sub, name: 'Firstname Lastname'}),
      }),
      jwks: {keys: [{
        kty: 'EC',
        crv: 'P-256',
        d: 'K9xfPv773dZR22TVUB80xouzdF7qCg5cWjPjkHyv7Ws',
        x: 'FWZ9rSkLt6Dx9E3pxLybhdM6xgR5obGsj5_pqmnz5J4',
        y: '_n8G69C-A2Xl4xUW2lF0i8ZGZnk_KPYrhv4GbTGu5G4',
        use: 'sig',
      }]},
      ttl: {AccessToken: 3600, Grant: 3600, IdToken: 3600, Interaction: 3600, Session: 3600},
    });
    this._server.on('request', this._provider.callback());
    // Same shortcut as the HTTP helper: skip past the login + consent UI by
    // accepting the username in a query parameter.
    this._provider.app.use(async (ctx, next) => {
      const {request: {method, path: p, query}} = ctx;
      if (!p.startsWith('/interaction/') || method !== 'GET') return await next();
      const details = await this._provider.interactionDetails(ctx.req, ctx.res);
      if (Object.entries(query).length === 0) {
        ctx.response.body = `waiting for ${details.prompt.name}`;
        ctx.response.status = 200;
        return;
      }
      switch (details.prompt.name) {
        case 'login':
          return await this._provider.interactionFinished(ctx.req, ctx.res,
              {login: {accountId: query.login, remember: false}});
        case 'consent': {
          const grant = details.grantId
            ? await this._provider.Grant.find(details.grantId)
            : new this._provider.Grant({
              accountId: details.session.accountId,
              clientId: details.params.client_id,
            });
          const {prompt: {details: d}} = details;
          if (d.missingOIDCScope) grant.addOIDCScope(d.missingOIDCScope.join(' '));
          if (d.missingOIDCClaims) grant.addOIDCClaims(d.missingOIDCClaims);
          if (d.missingResourceScopes) {
            for (const [r, s] of Object.entries(d.missingResourceScopes)) {
              grant.addResourceScope(r, s.join(' '));
            }
          }
          const grantId = await grant.save();
          return await this._provider.interactionFinished(ctx.req, ctx.res,
              {consent: details.grantId ? {} : {grantId}});
        }
      }
      return await next();
    });
  }

  async stop() {
    if (this._server == null) return;
    await httpsClose.call(this._server);
    this._server = null;
  }
}

describe(__filename, function () {
  let provider;
  let pems; // {key, cert, certPath} from generateSelfSignedCert()
  const backup = {};
  const client = {client_id: 'the_client_id', client_secret: 'the_client_secret'};

  before(async function () {
    await common.init();
    backup.settings = {
      requireAuthentication: settings.requireAuthentication,
      requireAuthorization: settings.requireAuthorization,
      users: settings.users,
    };
    // Self-signed cert valid for localhost. The same PEM is used as both
    // the server cert AND the CA bundle the plugin trusts.
    pems = generateSelfSignedCert();

    provider = new HttpsOidcProvider();
    await provider.start({
      tls: {key: pems.key, cert: pems.cert},
      clients: [{
        ...client,
        redirect_uris: [new URL('/ep_openid_connect/callback', common.baseUrl).href],
      }],
    });
  });

  beforeEach(function () {
    settings.requireAuthentication = true;
    settings.requireAuthorization = false;
    settings.users = {};
  });

  afterEach(function () {
    settings.requireAuthentication = backup.settings.requireAuthentication;
    settings.requireAuthorization = backup.settings.requireAuthorization;
    settings.users = backup.settings.users;
  });

  after(async function () {
    if (provider != null) await provider.stop();
    provider = null;
    if (pems && pems.dir) try { fs.rmSync(pems.dir, {recursive: true, force: true}); } catch (_) { /* ignore */ }
  });

  describe('loadCaBundle', function () {
    const {loadCaBundle} = epOpenidConnect.exportedForTestingOnly;

    it('returns null for an empty / missing value', function () {
      assert.equal(loadCaBundle(undefined), null);
      assert.equal(loadCaBundle(null), null);
      assert.equal(loadCaBundle(''), null);
    });

    it('returns inline PEM content unchanged', function () {
      assert.equal(loadCaBundle(pems.cert), pems.cert);
    });

    it('reads PEM content from a path', function () {
      assert.equal(loadCaBundle(pems.certPath), pems.cert);
    });

    it('throws on a non-existent path', function () {
      assert.throws(() => loadCaBundle('/this/path/does/not/exist.pem'),
          /ENOENT|no such file/);
    });
  });

  describe('discovery against a self-signed HTTPS provider', function () {
    const baseSettings = () => ({
      ...client,
      base_url: common.baseUrl,
      issuer: provider.issuer,
      scope: ['openid', 'etherpad'],
    });

    it('fails without the ca setting', async function () {
      // Discovery has to hit https://localhost:PORT/.well-known/... and
      // there's no CA on the system trust store that signed our cert. The
      // outer error from openid-client is the generic `TypeError: fetch
      // failed`; the underlying TLS reason lives in err.cause.
      await assert.rejects(
          epOpenidConnect.loadSettings('loadSettings', {settings: {ep_openid_connect: {
            ...baseSettings(),
          }}}),
          (err) => {
            const messages = [];
            for (let e = err; e != null; e = e.cause) {
              if (e.message) messages.push(String(e.message));
              if (e.code) messages.push(String(e.code));
            }
            const joined = messages.join(' | ');
            return /self-signed|self signed|unable to verify|UNABLE_TO_VERIFY_LEAF_SIGNATURE|CERT|TLS/i.test(joined);
          });
    });

    it('succeeds when ca points to a file', async function () {
      await epOpenidConnect.loadSettings('loadSettings', {settings: {ep_openid_connect: {
        ...baseSettings(),
        ca: pems.certPath,
      }}});
      // No throw means discovery completed against the self-signed IdP.
    });

    it('succeeds when ca contains inline PEM content', async function () {
      await epOpenidConnect.loadSettings('loadSettings', {settings: {ep_openid_connect: {
        ...baseSettings(),
        ca: pems.cert,
      }}});
    });
  });
});
