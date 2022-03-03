'use strict';

const MemoryAdapter = require('oidc-provider/lib/adapters/memory_adapter');
const Provider = require('oidc-provider');
const common = require('ep_etherpad-lite/tests/backend/common');
const http = require('http');
const util = require('util');

const httpListen = util.promisify(http.Server.prototype.listen);
const httpClose = util.promisify(http.Server.prototype.close);
const logger = common.logger;

// No-op subclass to silence warnings about using MemoryAdapter.
class Adapter extends MemoryAdapter {}

class OidcProvider {
  async start(options) {
    await this.stop();
    this._server = http.createServer();
    await httpListen.call(this._server, 0, 'localhost');
    this.issuer = `http://localhost:${this._server.address().port}/`;
    this._provider = new Provider(this.issuer, Object.assign({
      adapter: Adapter,
      claims: {
        etherpad: [
          'etherpad_is_admin',
          'etherpad_readOnly',
          'etherpad_canCreate',
          'name',
          'prop',
        ],
      },
      cookies: {
        keys: [common.randomString()],
      },
      features: {
        devInteractions: {enabled: false},
      },
      findAccount: async (ctx, sub, token) => ({
        accountId: sub,
        claims: async (use, scope, claims, rejected) => ({
          sub,
          name: 'Firstname Lastname',
          etherpad_is_admin: sub.includes('admin'),
          etherpad_readOnly: !sub.includes('admin') && sub.includes('readOnly'),
          etherpad_canCreate:
              sub.includes('admin') || (!sub.includes('readOnly') && !sub.includes('noCreate')),
          ...(sub === 'claimNull' ? {prop: null} : sub === 'claimVal' ? {prop: 'claimValue'} : {}),
        }),
      }),
      jwks: {
        /* eslint-disable max-len */
        keys: [
          {
            d: 'VEZOsY07JTFzGTqv6cC2Y32vsfChind2I_TTuvV225_-0zrSej3XLRg8iE_u0-3GSgiGi4WImmTwmEgLo4Qp3uEcxCYbt4NMJC7fwT2i3dfRZjtZ4yJwFl0SIj8TgfQ8ptwZbFZUlcHGXZIr4nL8GXyQT0CK8wy4COfmymHrrUoyfZA154ql_OsoiupSUCRcKVvZj2JHL2KILsq_sh_l7g2dqAN8D7jYfJ58MkqlknBMa2-zi5I0-1JUOwztVNml_zGrp27UbEU60RqV3GHjoqwI6m01U7K0a8Q_SQAKYGqgepbAYOA-P4_TLl5KC4-WWBZu_rVfwgSENwWNEhw8oQ',
            dp: 'E1Y-SN4bQqX7kP-bNgZ_gEv-pixJ5F_EGocHKfS56jtzRqQdTurrk4jIVpI-ZITA88lWAHxjD-OaoJUh9Jupd_lwD5Si80PyVxOMI2xaGQiF0lbKJfD38Sh8frRpgelZVaK_gm834B6SLfxKdNsP04DsJqGKktODF_fZeaGFPH0',
            dq: 'F90JPxevQYOlAgEH0TUt1-3_hyxY6cfPRU2HQBaahyWrtCWpaOzenKZnvGFZdg-BuLVKjCchq3G_70OLE-XDP_ol0UTJmDTT-WyuJQdEMpt_WFF9yJGoeIu8yohfeLatU-67ukjghJ0s9CBzNE_LrGEV6Cup3FXywpSYZAV3iqc',
            e: 'AQAB',
            kty: 'RSA',
            n: 'xwQ72P9z9OYshiQ-ntDYaPnnfwG6u9JAdLMZ5o0dmjlcyrvwQRdoFIKPnO65Q8mh6F_LDSxjxa2Yzo_wdjhbPZLjfUJXgCzm54cClXzT5twzo7lzoAfaJlkTsoZc2HFWqmcri0BuzmTFLZx2Q7wYBm0pXHmQKF0V-C1O6NWfd4mfBhbM-I1tHYSpAMgarSm22WDMDx-WWI7TEzy2QhaBVaENW9BKaKkJklocAZCxk18WhR0fckIGiWiSM5FcU1PY2jfGsTmX505Ub7P5Dz75Ygqrutd5tFrcqyPAtPTFDk8X1InxkkUwpP3nFU5o50DGhwQolGYKPGtQ-ZtmbOfcWQ',
            p: '5wC6nY6Ev5FqcLPCqn9fC6R9KUuBej6NaAVOKW7GXiOJAq2WrileGKfMc9kIny20zW3uWkRLm-O-3Yzze1zFpxmqvsvCxZ5ERVZ6leiNXSu3tez71ZZwp0O9gys4knjrI-9w46l_vFuRtjL6XEeFfHEZFaNJpz-lcnb3w0okrbM',
            q: '3I1qeEDslZFB8iNfpKAdWtz_Wzm6-jayT_V6aIvhvMj5mnU-Xpj75zLPQSGa9wunMlOoZW9w1wDO1FVuDhwzeOJaTm-Ds0MezeC4U6nVGyyDHb4CUA3ml2tzt4yLrqGYMT7XbADSvuWYADHw79OFjEi4T3s3tJymhaBvy1ulv8M',
            qi: 'wSbXte9PcPtr788e713KHQ4waE26CzoXx-JNOgN0iqJMN6C4_XJEX-cSvCZDf4rh7xpXN6SGLVd5ibIyDJi7bbi5EQ5AXjazPbLBjRthcGXsIuZ3AtQyR0CEWNSdM7EyM5TRdyZQ9kftfz9nI03guW3iKKASETqX2vh0Z8XRjyU',
            use: 'sig',
          },
          {
            crv: 'P-256',
            d: 'K9xfPv773dZR22TVUB80xouzdF7qCg5cWjPjkHyv7Ws',
            kty: 'EC',
            use: 'sig',
            x: 'FWZ9rSkLt6Dx9E3pxLybhdM6xgR5obGsj5_pqmnz5J4',
            y: '_n8G69C-A2Xl4xUW2lF0i8ZGZnk_KPYrhv4GbTGu5G4',
          },
        ],
        /* eslint-enable max-len */
      },
      ttl: {
        // Silence warnings.
        AccessToken: 3600,
        Grant: 3600,
        IdToken: 3600,
        Interaction: 3600,
        Session: 3600,
      },
    }, options));
    this._server.on('request', this._provider.callback());

    // Install middleware that provides fake login and consent pages. This code would be prettier,
    // but I wanted to avoid pulling in dependencies such as express or koa-route + koa-bodyparser.
    this._provider.app.use(async (ctx, next) => {
      const {request: {method, path, query}} = ctx;
      if (!path.startsWith('/interaction/') || method !== 'GET') return await next();
      const interactionDetails = await this._provider.interactionDetails(ctx.req, ctx.res);
      if (Object.entries(query).length === 0) {
        // This is where we would normally present a login or consent page. Just print the prompt
        // name to help with debugging.
        ctx.response.body = `waiting for ${interactionDetails.prompt.name}`;
        ctx.response.status = 200;
        return;
      }
      // Normally the login and consent pages would have a form that POSTs to the same URL, but for
      // convenience this code just uses GET with a query parameter.
      switch (interactionDetails.prompt.name) {
        case 'login': {
          const result = query.login.includes('fail')
            ? {error: 'access_denied', error_description: 'injected failure'}
            : {login: {accountId: query.login, remember: false}};
          // This is test code; no need for username or password checking.
          return await this._provider.interactionFinished(ctx.req, ctx.res, result);
        }
        case 'consent': {
          // The amount of boilerplate code required to handle basic consent interaction is much
          // higher than I would have expected. I don't understand this code; it is based on
          // https://github.com/panva/node-oidc-provider/blob/039a55a0ab24cd4f6aa5831b829cfb2cc1337866/example/routes/express.js#L116-L152
          const grant = interactionDetails.grantId
            ? await this._provider.Grant.find(interactionDetails.grantId)
            : new this._provider.Grant({
              accountId: interactionDetails.session.accountId,
              clientId: interactionDetails.params.client_id,
            });
          const {prompt: {details}} = interactionDetails;
          if (details.missingOIDCScope) grant.addOIDCScope(details.missingOIDCScope.join(' '));
          if (details.missingOIDCClaims) grant.addOIDCClaims(details.missingOIDCClaims);
          if (details.missingResourceScopes) {
            for (const [indicator, scopes] of Object.entries(details.missingResourceScopes)) {
              grant.addResourceScope(indicator, scopes.join(' '));
            }
          }
          const grantId = await grant.save();
          return await this._provider.interactionFinished(ctx.req, ctx.res, {
            consent: interactionDetails.grantId ? {} : {grantId},
          });
        }
      }
      return await next();
    });

    logger.info(`Test OpenID Connect provider listening at ${this.issuer}`);
  }

  async stop() {
    if (this._server == null) return;
    await httpClose.call(this._server);
    this._server = null;
  }
}
module.exports = OidcProvider;
