'use strict';

const assert = require('assert').strict;
const common = require('ep_etherpad-lite/tests/backend/common');
const openidClient = require('openid-client');
const http = require('http');
const login = require('./login');
const supertest = require('supertest');
const util = require('util');

const logger = common.logger;

class OidcClient {
  get callbackUrl() {
    return `http://localhost:${this._server.address().port}/callback`;
  }

  async start(issuerUrl, settings = {}) {
    await this.stop();
    this._issuer = issuerUrl;
    this._server = http.createServer();
    this._server.on('request', (req, res) => this._handleRequest(req, res));
    await util.promisify(this._server.listen).call(this._server, 0, 'localhost');
    const issuer = await openidClient.Issuer.discover(issuerUrl);
    this._client = await issuer.Client.register({
      ...settings,
      redirect_uris: [this.callbackUrl],
      response_types: ['code'],
    });
    this._callbackChecks = new Map();
    this._callbackResults = new Map();
    logger.info(`Test OIDC client callback: ${this.callbackUrl}`);
  }

  async stop() {
    if (this._server == null) return;
    await util.promisify(this._server.close).call(this._server);
    this._server = null;
  }

  async authenticate(scope, username) {
    const agent = supertest.agent('');
    const state = openidClient.generators.state();
    const commonParams = {nonce: openidClient.generators.nonce(), scope, state};
    const codeVerifier = openidClient.generators.codeVerifier();
    this._callbackChecks.set(state, {...commonParams, code_verifier: codeVerifier});
    const results = new Promise((resolve) => this._callbackResults.set(state, resolve));
    const url = this._client.authorizationUrl({
      ...commonParams,
      code_challenge: openidClient.generators.codeChallenge(codeVerifier),
      code_challenge_method: 'S256',
    });
    const res = await login(agent, this._issuer, url, username);
    assert(res.request.url.startsWith(this.callbackUrl));
    assert.equal(res.status, 200);
    this._callbackChecks.delete(state);
    this._callbackResults.delete(state);
    return await results;
  }

  async _handleRequest(req, res) {
    try {
      const url = new URL(req.url, `http://${req.headers.host}/`);
      if (req.method !== 'GET' || url.pathname !== '/callback') return res.end();
      const params = this._client.callbackParams(req);
      if (!params.state) throw new Error('missing state from callback params');
      const checks = this._callbackChecks.get(params.state);
      if (checks == null) throw new Error('missing callback checks');
      const tokenset = await this._client.callback(this.callbackUrl, params, checks);
      const userinfo = await this._client.userinfo(tokenset);
      this._callbackResults.get(params.state)({tokenset, userinfo});
      res.statusCode = 200;
      res.write('success');
    } catch (err) {
      logger.error(`Error while handling HTTP request in OidcClient: ${err.stack || err}`);
      res.statusCode = 500;
    }
    res.end();
  }

  async revokeToken(token, tokenType) {
    await this._client.revoke(token, tokenType);
  }
}
module.exports = OidcClient;
