'use strict';

const Ajv = require('ajv/dist/jtd');
const {URL} = require('url');
const {Issuer, generators} = require('@etherpad/node-openid-client');

let logger = {};
for (const level of ['debug', 'info', 'warn', 'error']) {
  logger[level] = console[level].bind(console, 'ep_openid_connect:');
}
const defaultSettings = {
  prohibited_usernames: ['admin', 'guest'],
  scope: ['openid'],
  user_properties: {},
};
let settings;
let oidcClient = null;

const validSettings = new Ajv().compile({
  properties: {
    base_url: {type: 'string'},
    client_id: {type: 'string'},
    client_secret: {type: 'string'},
  },
  optionalProperties: {
    issuer: {type: 'string'},
    issuer_metadata: {},
    prohibited_usernames: {elements: {type: 'string'}},
    scope: {elements: {type: 'string'}},
    user_properties: {values: {
      optionalProperties: {
        claim: {type: 'string'},
        default: {type: 'string'},
      },
      nullable: true,
    }},
  },
});

const ep = (endpoint) => `/ep_openid_connect/${endpoint}`;
const endpointUrl = (endpoint) => new URL(ep(endpoint).substr(1), settings.base_url).toString();

const validateSubClaim = (sub) => {
  if (typeof sub !== 'string' || // 'sub' claim must exist as a string per OIDC spec.
      sub === '' || // Empty string doesn't make sense.
      sub === '__proto__' || // Prevent prototype pollution.
      settings.prohibited_usernames.includes(sub)) {
    throw new Error('invalid sub claim');
  }
};

const discoverIssuer = async (issuerUrl) => {
  issuerUrl = new URL(issuerUrl);
  // https://openid.net/specs/openid-connect-discovery-1_0.html#IssuerDiscovery says that the URI
  // must not have query or fragment components.
  if (issuerUrl.search) {
    throw new Error(`Unexpected query in issuer URL (${issuerUrl}): ${issuerUrl.search}`);
  }
  if (issuerUrl.hash) {
    throw new Error(`Unexpected fragment in issuer URL (${issuerUrl}): ${issuerUrl.hash}`);
  }
  let issuer;
  try {
    issuer = await Issuer.discover(issuerUrl.href);
  } catch (err) {
    // The URL used to get the issuer metadata doesn't exactly follow RFC 8615; see:
    // https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfig
    const discoveryUrl = new URL(issuerUrl);
    if (!discoveryUrl.pathname.includes('/.well-known/')) {
      discoveryUrl.pathname =
          `${discoveryUrl.pathname.replace(/\/$/, '')}/.well-known/openid-configuration`;
    }
    logger.error(
        'Failed to discover issuer metadata via OpenID Connect Discovery ' +
        '(https://openid.net/specs/openid-connect-discovery-1_0.html). ' +
        `Does your issuer support Discovery? (hint: ${discoveryUrl})`);
    throw err;
  }
  logger.info('OpenID Connect Discovery complete.');
  return issuer;
};

const getIssuer = async (settings) => {
  if (settings.issuer) return await discoverIssuer(settings.issuer);
  return new Issuer(settings.issuer_metadata);
};

exports.init_ep_openid_connect = async (hookName, {logger: l}) => {
  if (l != null) logger = l;
};

exports.loadSettings = async (hookName, {settings: {ep_openid_connect: s = {}}}) => {
  oidcClient = null;
  settings = null;
  if (!validSettings(s)) {
    logger.error('Invalid settings. Detailed validation errors:', validSettings.errors);
    return;
  }
  if ((s.issuer == null) === (s.issuer_metadata == null)) {
    logger.error('Either ep_openid_connect.issuer or .issuer_metadata must be set (but not both)');
    return;
  }
  if ('username' in (s.user_properties || {})) {
    logger.error('ep_openid_connect.user_properties.username must not be set');
    return;
  }
  settings = {
    ...defaultSettings,
    ...s,
    user_properties: {
      displayname: {claim: 'name'},
      ...s.user_properties,
      // The username property must always match the key used in settings.users.
      username: {claim: 'sub'},
    },
  };
  // Make sure base_url ends with '/' so that relative URLs are appended:
  if (!settings.base_url.endsWith('/')) settings.base_url += '/';
  logger.debug('Settings:', {...settings, client_secret: '********'});
  oidcClient = new (await getIssuer(settings)).Client({
    client_id: settings.client_id,
    client_secret: settings.client_secret,
    response_types: ['code'],
    redirect_uris: [endpointUrl('callback')],
  });
  logger.info('Configured.');
};

exports.expressCreateServer = (hookName, {app}) => {
  logger.debug('Configuring auth routes');
  app.get(ep('callback'), async (req, res, next) => {
    // This handler MUST NOT redirect to a page that requires authentication if there is a problem,
    // otherwise the user could be caught in an infinite redirect loop.
    try {
      logger.debug(`Processing ${req.url}`);
      if (oidcClient == null) {
        logger.warn('Not configured; ignoring request.');
        return next();
      }
      const params = oidcClient.callbackParams(req);
      const oidcSession = req.session.ep_openid_connect || {};
      if (oidcSession.callbackChecks == null) throw new Error('missing authentication checks');
      const tokenset =
          await oidcClient.callback(endpointUrl('callback'), params, oidcSession.callbackChecks);
      const userinfo = await oidcClient.userinfo(tokenset);
      validateSubClaim(userinfo.sub);
      // The user has successfully authenticated, but don't set req.session.user here -- do it in
      // the authenticate hook so that Etherpad can log the authentication success. However, DO "log
      // out" the previous user to force the authenticate hook to run in case the user was already
      // authenticated as someone else.
      delete req.session.user;
      // userinfo should not be stored in req.session until after all checks have passed. (Otherwise
      // it would be too easy to accidentally introduce a vulnerability.)
      oidcSession.userinfo = userinfo;
      res.redirect(303, oidcSession.next || settings.base_url);
      // Defer deletion of state until success so that the user can reload the page to retry after a
      // transient backchannel failure.
      delete oidcSession.callbackChecks;
      delete oidcSession.next;
    } catch (err) {
      return next(err);
    }
  });
  app.get(ep('login'), (req, res, next) => {
    logger.debug(`Processing ${req.url}`);
    if (oidcClient == null) {
      logger.warn('Not configured; ignoring request.');
      return next();
    }
    if (req.session.ep_openid_connect == null) req.session.ep_openid_connect = {};
    const oidcSession = req.session.ep_openid_connect;
    const commonParams = {
      nonce: generators.nonce(),
      scope: settings.scope.join(' '),
      state: generators.state(),
    };
    oidcSession.callbackChecks = {
      ...commonParams,
      code_verifier: generators.codeVerifier(), // RFC7636
    };
    res.redirect(303, oidcClient.authorizationUrl({
      ...commonParams,
      // RFC7636
      code_challenge: generators.codeChallenge(oidcSession.callbackChecks.code_verifier),
      code_challenge_method: 'S256',
    }));
  });
  app.get(ep('logout'), (req, res, next) => {
    logger.debug(`Processing ${req.url}`);
    if (oidcClient == null) {
      logger.warn('Not configured; ignoring request.');
      return next();
    }
    req.session.destroy(() => res.redirect(303, settings.base_url));
  });
};

exports.authenticate = (hookName, {req, res, users}) => {
  if (oidcClient == null) return;
  logger.debug('authenticate hook for', req.url);
  const {ep_openid_connect: {userinfo} = {}} = req.session;
  if (userinfo == null) { // Nullish means the user isn't authenticated.
    // Out of an abundance of caution, clear out the old state, nonce, and userinfo (if present) to
    // force regeneration.
    delete req.session.ep_openid_connect;
    // Authn failed. Let another plugin try to authenticate the user.
    return;
  }
  // Successfully authenticated.
  logger.info('Successfully authenticated user with userinfo:', userinfo);
  req.session.user = users[userinfo.sub];
  if (req.session.user == null) req.session.user = users[userinfo.sub] = {};
  for (const [propName, descriptor] of Object.entries(settings.user_properties)) {
    if (descriptor == null) {
      delete req.session.user[propName];
    } else if (descriptor.claim != null && descriptor.claim in userinfo) {
      req.session.user[propName] = userinfo[descriptor.claim];
    } else if ('default' in descriptor && !(propName in req.session.user)) {
      req.session.user[propName] = descriptor.default;
    }
  }
  logger.debug('User properties:', req.session.user);
  return true;
};

exports.authnFailure = (hookName, {req, res}) => {
  if (oidcClient == null) return;
  // Normally the user is redirected to the login page which would then redirect the user back once
  // authenticated. For non-GET requests, send a 401 instead because users can't be redirected back.
  // Also send a 401 if an Authorization header is present to facilitate API error handling.
  //
  // 401 is the status that most closely matches the desired semantics. However, RFC7235 section
  // 3.1 says, "The server generating a 401 response MUST send a WWW-Authenticate header field
  // containing at least one challenge applicable to the target resource." Etherpad uses a token
  // (signed session identifier) transmitted via cookie for authentication, but there is no
  // standard authentication scheme name for that. So we use a non-standard name here.
  //
  // We could theoretically implement Bearer authorization (RFC6750), but it's unclear to me how
  // to do this correctly and securely:
  //   * The userinfo endpoint is meant for the OAuth client, not the resource server, so it
  //     shouldn't be used to look up claims.
  //   * In general, access tokens might be opaque (not JWTs) so we can't get claims by parsing
  //     them.
  //   * The token introspection endpoint should return scope and subject (I think?), but probably
  //     not claims.
  //   * If claims can't be used to convey access level, how is it conveyed? Scope? Resource
  //     indicators (RFC8707)?
  //   * How is intended audience checked? Or is introspection guaranteed to do that for us?
  //   * Should tokens be limited to a particular pad?
  //   * Bearer tokens are only meant to convey authorization; authentication is handled by the
  //     authorization server. Should Bearer tokens be processed during the authorize hook?
  //   * How should bearer authentication interact with authorization plugins?
  //   * How should bearer authentication interact with plugins that add new endpoints?
  //   * Would we have to implement our own OAuth server to issue access tokens?
  res.header('WWW-Authenticate', 'Etherpad');
  if (!['GET', 'HEAD'].includes(req.method) || req.headers.authorization) {
    res.status(401).end();
    return true;
  }
  if (req.session.ep_openid_connect == null) req.session.ep_openid_connect = {};
  req.session.ep_openid_connect.next = new URL(req.url.slice(1), settings.base_url).toString();
  res.redirect(303, endpointUrl('login'));
  return true;
};

exports.preAuthorize = (hookName, {req}) => {
  if (oidcClient == null) return;
  if (req.path.startsWith(ep(''))) return true;
  return;
};

exports.exportedForTestingOnly = {
  defaultSettings,
};
