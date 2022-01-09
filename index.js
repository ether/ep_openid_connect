'use strict';

const log4js = require('ep_etherpad-lite/node_modules/log4js');
const {URL} = require('url');
const {Issuer, generators} = require('openid-client');
const authorManager = require('ep_etherpad-lite/node/db/AuthorManager');

const logger = log4js.getLogger('ep_openid_connect');
const defaultSettings = {
  displayname_claim: 'name',
  permit_displayname_change: false,
  prohibited_usernames: ['admin', 'guest'],
  scope: ['openid'],
  user_properties: {},
};
const settings = {...defaultSettings};
let oidcClient = null;

const ep = (endpoint) => `/ep_openid_connect/${endpoint}`;
const endpointUrl = (endpoint) => new URL(ep(endpoint).substr(1), settings.base_url).toString();

const validateSubClaim = (sub) => {
  try {
    if (typeof sub !== 'string' || // 'sub' claim must exist as a string per OIDC spec.
        sub === '' || // Empty string doesn't make sense.
        sub === '__proto__' || // Prevent prototype pollution.
        settings.prohibited_usernames.includes(sub)) {
      throw new Error('invalid sub claim');
    }
  } catch (err) {
    err.error = 'invalid_token'; // RFC6750 section 3.1.
    err.error_description = err.message;
    throw err;
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

exports.loadSettings = async (hookName, {settings: {ep_openid_connect: config = {}}}) => {
  Object.assign(settings, config);
  for (const setting of ['base_url', 'client_id', 'client_secret']) {
    if (!settings[setting]) {
      logger.error(`Required setting missing from settings.json: ep_openid_connect.${setting}`);
      return;
    }
  }
  if (!settings.issuer && !settings.issuer_metadata) {
    logger.error(
        'Either ep_openid_connect.issuer or ep_openid_connect.issuer_metadata must be set');
    return;
  }
  if (settings.issuer && settings.issuer_metadata) {
    logger.warn('Ignoring ep_openid_connect.issuer_metadata setting ' +
                'because ep_openid_connect.issuer is set');
  }
  if (settings.response_types) {
    logger.warn('Ignoring ep_openid_connect.response_types setting (it is no longer used)');
    delete settings.response_types;
  }
  // Make sure base_url ends with '/' so that relative URLs are appended:
  if (!settings.base_url.endsWith('/')) settings.base_url += '/';
  settings.user_properties = {
    displayname: {claim: settings.displayname_claim},
    ...settings.user_properties,
    // The username property must always match the key used in settings.users.
    username: {claim: 'sub'},
  };
  logger.debug('Settings:', {...settings, client_secret: '********'});
  oidcClient = new (await getIssuer(settings)).Client({
    client_id: settings.client_id,
    client_secret: settings.client_secret,
    response_types: ['code'],
    redirect_uris: [endpointUrl('callback')],
  });
  logger.info('Configured.');
};

exports.clientVars = (hookName, context) => {
  if (oidcClient == null) return;
  const {permit_displayname_change} = settings;
  return {ep_openid_connect: {permit_displayname_change}};
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

const userinfoFromBearerToken = async ({headers: {authorization = ''}}) => {
  if (!/^Bearer(?: .*)?$/.test(authorization)) return null;
  logger.debug('checking Bearer token');
  // RFC6749 section A.12 says that access tokens consist of characters 0x20 through 0x7E, but
  // RFC6750 section 2.1 only allows a subset of those characters without explanation. ¯\_(ツ)_/¯
  // Because the original token string isn't encoded before putting it in the Authenticate header,
  // just use whatever the client sends. If it contains invalid characters, introspection will fail.
  const [, token] = /^Bearer +(.*)/.exec(authorization) || [];
  try {
    if (!token) throw new Error('missing Bearer token');
  } catch (err) {
    err.error = 'invalid_request'; // RFC6750 section 3.1.
    err.error_description = err.message;
    throw err;
  }
  const [insp, userinfo] = await Promise.all([
    oidcClient.introspect(token, 'access_token'),
    oidcClient.userinfo(token),
  ]);
  logger.debug('token introspection data:', insp);
  logger.debug('userinfo:', userinfo);
  try {
    if (!insp.active) throw new Error('Bearer token not active');
    // RFC7662 says insp.token_type is optional, but check it if it's there.
    if (insp.token_type != null && insp.token_type !== 'Bearer') {
      throw new Error('token type is not Bearer');
    }
    // RFC7662 says insp.sub is optional, but check it if it's there.
    if (insp.sub != null && insp.sub !== userinfo.sub) {
      throw new Error('sub claim mismatch');
    }
  } catch (err) {
    err.error = 'invalid_token'; // RFC6750 section 3.1.
    err.error_description = err.message;
    throw err;
  }
  try {
    // RFC7662 says insp.scope is optional, but we require it so that we can check it.
    if (insp.scope == null) throw new Error('unknown Bearer token scope');
    const scopes = insp.scope.split(/ +/);
    for (const scope of settings.scope) {
      if (!scopes.includes(scope)) throw new Error(`Bearer token lacks scope ${scope}`);
    }
  } catch (err) {
    err.error = 'insufficient_scope'; // RFC6750 section 3.1.
    err.error_description = err.message;
    throw err;
  }
  validateSubClaim(userinfo.sub);
  return userinfo;
};

exports.authenticate = async (hookName, {req, res, users}) => {
  if (oidcClient == null) return;
  logger.debug('authenticate hook for', req.url);
  let {ep_openid_connect: {userinfo} = {}} = req.session;
  try {
    if (userinfo == null) userinfo = await userinfoFromBearerToken(req);
    if (userinfo == null) throw new Error('not authenticated');
  } catch (err) {
    logger.debug(`authentication failure: ${err}`);
    // oidcClient sometimes throws errors with `.error*` properties that can (and should) be
    // returned in the WWW-Authenticate header. The code above also sets those properties in thrown
    // exceptions. Save the error so we can use those properties if present.
    res.locals.ep_openid_connect = {err};
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
    if (descriptor.claim != null && descriptor.claim in userinfo) {
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
  const wwwAuthenticateFields = {
    realm: 'ep_openid_connect',
    scope: settings.scope.join(' '),
  };
  // Include the special error properties from the thrown error object, if present.
  const {ep_openid_connect: {err = {}} = {}} = res.locals;
  for (const field of ['error', 'error_description', 'error_uri']) {
    if (typeof err[field] === 'string') wwwAuthenticateFields[field] = err[field];
  }
  const fieldsStr = Object.entries(wwwAuthenticateFields).map(([k, v]) => ` ${k}="${v}"`).join('');
  res.header('WWW-Authenticate', `Bearer${fieldsStr}`);
  // Normally the user is redirected to the login page which would then redirect the user back once
  // authenticated. For non-GET requests, send a 401 instead because users can't be redirected back.
  // Also send a 401 if an Authorization header is present to facilitate API error handling.
  if (!['GET', 'HEAD'].includes(req.method) || req.headers.authorization) {
    res.status(401).end();
    return true;
  }
  if (req.session.ep_openid_connect == null) req.session.ep_openid_connect = {};
  req.session.ep_openid_connect.next = new URL(req.url.slice(1), settings.base_url).toString();
  res.redirect(303, endpointUrl('login'));
  return true;
};

exports.handleMessage = async (hookName, {message, socket}) => {
  if (oidcClient == null) return;
  logger.debug('handleMessage hook', message);
  const {user: {displayname} = {}} = socket.client.request.session;
  if (!displayname) return;
  if (message.type === 'CLIENT_READY') {
    logger.debug(
        `CLIENT_READY ${socket.id}: Setting username for token ${message.token} to ${displayname}`
    );
    // TODO: author ID might come from session ID, not token.
    const authorId = await authorManager.getAuthor4Token(message.token);
    await authorManager.setAuthorName(authorId, displayname);
  } else if (message.type === 'COLLABROOM' && message.data.type === 'USERINFO_UPDATE') {
    if (message.data.userInfo.name !== displayname && !settings.permit_displayname_change) {
      message.data.userInfo.name = displayname;
    }
  }
};

exports.preAuthorize = (hookName, {req}) => {
  if (oidcClient == null) return;
  if (req.path.startsWith(ep(''))) return true;
  return;
};

exports.exportedForTestingOnly = {
  defaultSettings,
};
