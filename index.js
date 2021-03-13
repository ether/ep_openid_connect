'use strict';

const log4js = require('ep_etherpad-lite/node_modules/log4js');
const {URL} = require('url');
const {Issuer, generators} = require('openid-client');
const authorManager = require('ep_etherpad-lite/node/db/AuthorManager');

const logger = log4js.getLogger('ep_openid_connect');
const settings = {
  displayname_claim: 'name',
  response_types: ['code'],
  permit_displayname_change: false,
  prohibited_usernames: ['admin', 'guest'],
  scope: ['openid'],
  user_properties: {},
};
let oidcClient = null;

const ep = (endpoint) => `/ep_openid_connect/${endpoint}`;
const endpointUrl = (endpoint) => new URL(ep(endpoint).substr(1), settings.base_url).toString();

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
  // Make sure base_url ends with '/' so that relative URLs are appended:
  if (!settings.base_url.endsWith('/')) settings.base_url += '/';
  settings.user_properties = {
    displayname: {claim: settings.displayname_claim},
    ...settings.user_properties,
    // The username property must always match the key used in settings.users.
    username: {claim: 'sub'},
  };
  oidcClient = new (await getIssuer(settings)).Client({
    client_id: settings.client_id,
    client_secret: settings.client_secret,
    response_types: settings.response_types,
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
  if (oidcClient == null) return;
  logger.debug('Configuring auth routes');
  app.get(ep('callback'), (req, res, next) => {
    logger.debug(`Processing ${req.url}`);
    (async () => {
      const params = oidcClient.callbackParams(req);
      const oidcSession = req.session.ep_openid_connect || {};
      const {authParams} = oidcSession;
      if (authParams == null) throw new Error('no authentication paramters found in session state');
      const tokenset = await oidcClient.callback(endpointUrl('callback'), params, authParams);
      oidcSession.userinfo = await oidcClient.userinfo(tokenset);
      // The user has successfully authenticated, but don't set req.session.user here -- do it in
      // the authenticate hook so that Etherpad can log the authentication success. However, DO "log
      // out" the previous user to force the authenticate hook to run in case the user was already
      // authenticated as someone else.
      delete req.session.user;
      res.redirect(oidcSession.next || settings.base_url);
      // Defer deletion of state until success so that the user can reload the page to retry after a
      // transient backchannel failure.
      delete oidcSession.authParams;
      delete oidcSession.next;
    })().catch(next);
  });
  app.get(ep('login'), (req, res, next) => {
    logger.debug(`Processing ${req.url}`);
    if (req.session.ep_openid_connect == null) req.session.ep_openid_connect = {};
    const oidcSession = req.session.ep_openid_connect;
    oidcSession.next = req.query.redirect_uri || settings.base_url;
    oidcSession.authParams = {
      nonce: generators.nonce(),
      scope: settings.scope.join(' '),
      state: generators.state(),
    };
    res.redirect(oidcClient.authorizationUrl(oidcSession.authParams));
  });
  app.get(ep('logout'), (req, res) => req.session.destroy(() => res.redirect(settings.base_url)));
};

exports.authenticate = (hookName, {req, res, users}) => {
  if (oidcClient == null) return;
  logger.debug('authenticate hook for', req.url);
  const {session} = req;
  const {ep_openid_connect: {userinfo = {}} = {}} = session;
  const {sub} = userinfo;
  if (sub == null || // Nullish means the user isn't authenticated.
      typeof sub !== 'string' || // `sub` is used as the username, so it must be a string.
      sub === '' || // Empty string doesn't make sense.
      sub === '__proto__' || // Prevent prototype pollution.
      settings.prohibited_usernames.includes(sub)) {
    // Out of an abundance of caution, clear out the old state, nonce, and userinfo (if present) to
    // force regeneration.
    delete session.ep_openid_connect;
    // Authn failed. Let another plugin try to authenticate the user.
    return;
  }
  // Successfully authenticated.
  logger.info('Successfully authenticated user with userinfo:', userinfo);
  session.user = users[sub];
  if (session.user == null) session.user = users[sub] = {};
  for (const [propName, descriptor] of Object.entries(settings.user_properties)) {
    if (descriptor.claim != null && descriptor.claim in userinfo) {
      session.user[propName] = userinfo[descriptor.claim];
    } else if ('default' in descriptor && !(propName in session.user)) {
      session.user[propName] = descriptor.default;
    }
  }
  logger.debug('User properties:', session.user);
  return true;
};

exports.authnFailure = (hookName, {req, res}) => {
  if (oidcClient == null) return;
  const url = new URL(req.url.substr(1), settings.base_url).toString();
  res.redirect(`${endpointUrl('login')}?redirect_uri=${encodeURIComponent(url)}`);
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
