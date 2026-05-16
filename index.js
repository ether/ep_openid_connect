'use strict';

const Ajv = require('ajv/dist/jtd');
const {URL} = require('url');

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
let oidcConfig = null;
// openid-client@6 is ESM-only, so it must be loaded with a dynamic import from
// this CommonJS module. The reference is cached after the first call.
let oidc = null;
const loadOidc = async () => {
  if (oidc == null) oidc = await import('openid-client');
  return oidc;
};

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
    token_endpoint_auth_method: {enum: ['client_secret_basic', 'client_secret_post']},
    user_properties: {values: {
      optionalProperties: {
        claim: {type: 'string'},
        // `role` looks the named string up inside the `roles` claim's array
        // value. Used by IdPs like Azure/Entra that surface role assignments
        // via a single `roles` array claim instead of a dedicated claim per
        // property. Set the property to `true` when the role is present.
        role: {type: 'string'},
        // `default` is assigned verbatim to `req.session.user[propName]`,
        // so any JSON value (boolean for is_admin/readOnly/canCreate,
        // number, string, …) is fine. Use the JTD empty form so we don't
        // reject non-string defaults (#100).
        default: {},
      },
      nullable: true,
    }},
  },
});

const ep = (endpoint) => `/ep_openid_connect/${endpoint}`;
const endpointUrl = (endpoint) => new URL(ep(endpoint).substr(1), settings.base_url).toString();

const callbackUrlFromRequest = (req) => {
  const callbackUrl = new URL(endpointUrl('callback'));
  const requestUrl = new URL(req.originalUrl || req.url, settings.base_url);
  for (const [key, value] of requestUrl.searchParams) {
    callbackUrl.searchParams.append(key, value);
  }
  return callbackUrl;
};

const validateSubClaim = (sub) => {
  if (typeof sub !== 'string' || // 'sub' claim must exist as a string per OIDC spec.
      sub === '' || // Empty string doesn't make sense.
      sub === '__proto__' || // Prevent prototype pollution.
      settings.prohibited_usernames.includes(sub)) {
    throw new Error('invalid sub claim');
  }
};

const isHttp = (urlString) => {
  try {
    return new URL(urlString).protocol === 'http:';
  } catch (e) {
    return false;
  }
};

// Pick the token endpoint auth method to use, given the IdP's advertised
// `token_endpoint_auth_methods_supported` and any explicit override from
// settings. Pure; exported for unit testing.
//
// Preference order when no override is set:
//   1. `client_secret_post` if the IdP advertises it (matches openid-client@6's
//      own default and works with every public IdP we've tested — notably
//      GitLab.com, which rejects `client_secret_basic` at the token endpoint
//      even though it lists it in discovery).
//   2. `client_secret_basic` if the IdP advertises only that.
//   3. `client_secret_basic` if the IdP advertises nothing we recognise (RFC
//      8414 §2 says the absence of the field defaults to `client_secret_basic`).
const pickAuthMethod = (supported, override) => {
  if (override) return override;
  if (Array.isArray(supported)) {
    if (supported.includes('client_secret_post')) return 'client_secret_post';
    if (supported.includes('client_secret_basic')) return 'client_secret_basic';
  }
  return 'client_secret_basic';
};

const clientAuthFor = (method, secret) => {
  switch (method) {
    case 'client_secret_basic':
      // eslint-disable-next-line new-cap
      return oidc.ClientSecretBasic(secret);
    case 'client_secret_post':
      // eslint-disable-next-line new-cap
      return oidc.ClientSecretPost(secret);
    default:
      throw new Error(`Unsupported token endpoint auth method: ${method}`);
  }
};

const fetchServerMetadata = async (issuerUrl, clientId) => {
  const url = new URL(issuerUrl);
  // https://openid.net/specs/openid-connect-discovery-1_0.html#IssuerDiscovery says that the URI
  // must not have query or fragment components.
  if (url.search) {
    throw new Error(`Unexpected query in issuer URL (${url}): ${url.search}`);
  }
  if (url.hash) {
    throw new Error(`Unexpected fragment in issuer URL (${url}): ${url.hash}`);
  }
  // openid-client@6 rejects http:// issuers by default; opt back in for
  // localhost / private-network providers (matches v5 behaviour).
  const options = url.protocol === 'http:'
    ? {execute: [oidc.allowInsecureRequests]}
    : undefined;
  try {
    // Discovery fetches the .well-known/openid-configuration document. The
    // clientAuthentication argument is irrelevant for that HTTP request — it
    // only matters when the Configuration is later used to exchange a code
    // for a token — so we can pass `undefined` here and bind the real method
    // below once we know what the IdP supports.
    const tempConfig = await oidc.discovery(url, clientId, undefined, undefined, options);
    return tempConfig.serverMetadata();
  } catch (err) {
    // The URL used to get the issuer metadata doesn't exactly follow RFC 8615; see:
    // https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfig
    const discoveryUrl = new URL(url);
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
};

const buildConfig = async (settings) => {
  // Resolve the server metadata (either via discovery or from the inline
  // `issuer_metadata` blob) BEFORE choosing an auth method, so we can pick
  // one the IdP actually advertises.
  let serverMetadata;
  let phaseLog;
  if (settings.issuer) {
    serverMetadata = await fetchServerMetadata(settings.issuer, settings.client_id);
    phaseLog = 'OpenID Connect Discovery complete.';
  } else {
    serverMetadata = settings.issuer_metadata;
    phaseLog = 'Configured from issuer_metadata.';
  }
  const method = pickAuthMethod(
      serverMetadata && serverMetadata.token_endpoint_auth_methods_supported,
      settings.token_endpoint_auth_method);
  const clientAuth = clientAuthFor(method, settings.client_secret);
  const config = new oidc.Configuration(
      serverMetadata, settings.client_id, undefined, clientAuth);
  if (isHttp(serverMetadata && serverMetadata.issuer)) {
    oidc.allowInsecureRequests(config);
  }
  const source = settings.token_endpoint_auth_method ? 'configured' : 'auto-picked';
  logger.info(`${phaseLog} Token endpoint auth method: ${method} (${source}).`);
  return config;
};

exports.init_ep_openid_connect = async (hookName, {logger: l}) => {
  if (l != null) logger = l;
  await loadOidc();
};

exports.loadSettings = async (hookName, {settings: {ep_openid_connect: s = {}}}) => {
  oidcConfig = null;
  settings = null;
  await loadOidc();
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
  oidcConfig = await buildConfig(settings);
};

exports.expressCreateServer = (hookName, {app}) => {
  logger.debug('Configuring auth routes');
  app.get(ep('callback'), async (req, res, next) => {
    // This handler MUST NOT redirect to a page that requires authentication if there is a problem,
    // otherwise the user could be caught in an infinite redirect loop.
    try {
      logger.debug(`Processing ${req.url}`);
      if (oidcConfig == null) {
        logger.warn('Not configured; ignoring request.');
        return next();
      }
      const oidcSession = req.session.ep_openid_connect || {};
      if (oidcSession.callbackChecks == null) throw new Error('missing authentication checks');
      const tokens = await oidc.authorizationCodeGrant(oidcConfig, callbackUrlFromRequest(req), {
        expectedNonce: oidcSession.callbackChecks.nonce,
        expectedState: oidcSession.callbackChecks.state,
        pkceCodeVerifier: oidcSession.callbackChecks.code_verifier,
        idTokenExpected: true,
      });
      const claims = tokens.claims();
      const userinfo =
          await oidc.fetchUserInfo(oidcConfig, tokens.access_token, claims && claims.sub);
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
  app.get(ep('login'), async (req, res, next) => {
    try {
      logger.debug(`Processing ${req.url}`);
      if (oidcConfig == null) {
        logger.warn('Not configured; ignoring request.');
        return next();
      }
      if (req.session.ep_openid_connect == null) req.session.ep_openid_connect = {};
      const oidcSession = req.session.ep_openid_connect;
      const code_verifier = oidc.randomPKCECodeVerifier(); // RFC7636
      const code_challenge = await oidc.calculatePKCECodeChallenge(code_verifier);
      const nonce = oidc.randomNonce();
      const state = oidc.randomState();
      oidcSession.callbackChecks = {nonce, state, code_verifier};
      const url = oidc.buildAuthorizationUrl(oidcConfig, {
        redirect_uri: endpointUrl('callback'),
        scope: settings.scope.join(' '),
        nonce,
        state,
        code_challenge,
        code_challenge_method: 'S256',
      });
      res.redirect(303, url.toString());
    } catch (err) {
      return next(err);
    }
  });
  app.get(ep('logout'), (req, res, next) => {
    logger.debug(`Processing ${req.url}`);
    if (oidcConfig == null) {
      logger.warn('Not configured; ignoring request.');
      return next();
    }
    req.session.destroy(() => res.redirect(303, settings.base_url));
  });
};

exports.authenticate = (hookName, {req, res, users}) => {
  if (oidcConfig == null) return;
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
    } else if (descriptor.role != null && Array.isArray(userinfo.roles) &&
               userinfo.roles.includes(descriptor.role)) {
      // Boolean `true` (not the string `"true"`) so that the value works
      // directly with Etherpad's is_admin/readOnly/canCreate checks.
      req.session.user[propName] = true;
    } else if ('default' in descriptor && !(propName in req.session.user)) {
      req.session.user[propName] = descriptor.default;
    }
  }
  logger.debug('User properties:', req.session.user);
  return true;
};

exports.authnFailure = (hookName, {req, res}) => {
  if (oidcConfig == null) return;
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
  if (oidcConfig == null) return;
  if (req.path.startsWith(ep(''))) return true;
  return;
};

exports.exportedForTestingOnly = {
  callbackUrlFromRequest,
  defaultSettings,
  pickAuthMethod,
  validSettings,
};
