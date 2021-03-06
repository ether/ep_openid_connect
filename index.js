'use strict';

const log4js = require('ep_etherpad-lite/node_modules/log4js');
const {URL} = require('url');
const {Issuer, generators} = require('openid-client');
const authorManager = require('ep_etherpad-lite/node/db/AuthorManager');

const pluginName = 'ep_openid_connect';
const logger = log4js.getLogger(pluginName);
const settings = {
  displayname_claim: 'name',
  response_types: ['code'],
  permit_displayname_change: false,
  prohibited_usernames: ['admin', 'guest'],
};
let oidcClient = null;

const ep = (endpoint) => `/${pluginName}/${endpoint}`;
const endpointUrl = (endpoint) => new URL(ep(endpoint).substr(1), settings.base_url).toString();

exports.loadSettings = async (hookName, {settings: {[pluginName]: config = {}}}) => {
  Object.assign(settings, config);
  for (const setting of ['base_url', 'client_id', 'client_secret', 'issuer']) {
    if (!settings[setting]) {
      logger.error(`Required setting missing from settings.json: ${pluginName}.${setting}`);
      return;
    }
  }
  // Make sure base_url ends with '/' so that relative URLs are appended:
  if (!settings.base_url.endsWith('/')) settings.base_url += '/';
  oidcClient = new (await Issuer.discover(settings.issuer)).Client({
    client_id: settings.client_id,
    client_secret: settings.client_secret,
    response_types: settings.response_types,
    redirect_uris: [endpointUrl('callback')],
  });
  logger.info('Client discovery complete. Configured.');
};

exports.clientVars = (hookName, context) => {
  if (oidcClient == null) return;
  const {permit_displayname_change} = settings;
  return {[pluginName]: {permit_displayname_change}};
};

exports.expressCreateServer = (hookName, {app}) => {
  if (oidcClient == null) return;
  logger.debug('Configuring auth routes');
  app.get(ep('callback'), (req, res, next) => {
    logger.debug(`Processing ${req.url}`);
    (async () => {
      const params = oidcClient.callbackParams(req);
      const oidcSession = req.session[pluginName] || {};
      const {authParams} = oidcSession;
      if (authParams == null) throw new Error('no authentication paramters found in session state');
      const tokenset = await oidcClient.callback(endpointUrl('callback'), params, authParams);
      const userinfo = await oidcClient.userinfo(tokenset);
      if (settings.prohibited_usernames.indexOf(userinfo.sub) !== -1) {
        throw new Error(`authenticated user's 'sub' claim (${userinfo.sub}) is not permitted`);
      }
      oidcSession.userinfo = userinfo;
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
    if (req.session[pluginName] == null) req.session[pluginName] = {};
    const oidcSession = req.session[pluginName];
    oidcSession.next = req.query.redirect_uri || settings.base_url;
    oidcSession.authParams = {nonce: generators.nonce(), state: generators.state()};
    res.redirect(oidcClient.authorizationUrl(oidcSession.authParams));
  });
  app.get(ep('logout'), (req, res) => req.session.destroy(() => res.redirect(settings.base_url)));
};

exports.authenticate = (hookName, {req, res, users}) => {
  if (oidcClient == null) return;
  logger.debug('authenticate hook for', req.url);
  const {session} = req;
  const {[pluginName]: {userinfo = {}} = {}} = session;
  const {sub} = userinfo;
  if (sub == null) {
    // Out of an abundance of caution, clear out the old state, nonce, and userinfo (if present) to
    // force regeneration.
    delete session[pluginName];
    // Authn failed. Let another plugin try to authenticate the user.
    return;
  }
  // Successfully authenticated.
  if (users[sub] == null) users[sub] = {};
  session.user = users[sub];
  session.user.username = sub;
  session.user.displayname = userinfo[settings.displayname_claim] || session.user.displayname;
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
