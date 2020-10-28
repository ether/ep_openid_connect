'use strict';

/* global exports, require */

const log4js = require('ep_etherpad-lite/node_modules/log4js');
const {URL} = require('url');
const {Issuer, generators} = require('openid-client');
const authorManager = require('ep_etherpad-lite/node/db/AuthorManager');

const pluginName = 'ep_openid_connect';
const logger = log4js.getLogger(pluginName);
const settings = {};
let oidcClient = null;

const ep = (endpoint) => `/${pluginName}/${endpoint}`;
const endpointUrl = (endpoint) => new URL(ep(endpoint).substr(1), settings.base_url).toString();

exports.loadSettings = async (hookName, {settings: globalSettings}) => {
  const mySettings = globalSettings[pluginName];

  if (!mySettings) logger.error(`Expecting an ${pluginName} block in settings.`);
  for (const setting of ['base_url', 'client_id', 'client_secret', 'issuer']) {
    if (!mySettings[setting]) logger.error(`Expecting an ${pluginName}.${setting} setting.`);
  }
  Object.assign(settings, mySettings);
  // Make sure base_url ends with '/' so that relative URLs are appended:
  if (!settings.base_url.endsWith('/')) settings.base_url += '/';
  settings.displayname_claim = settings.displayname_claim || 'name';
  settings.response_types = settings.response_types || ['code'];
  settings.permit_displayname_change = settings.permit_displayname_change || false;
  settings.prohibited_usernames = settings.prohibited_usernames || ['admin', 'guest'];
  oidcClient = new (await Issuer.discover(settings.issuer)).Client({
    client_id: settings.client_id,
    client_secret: settings.client_secret,
    response_types: settings.response_types,
    redirect_uris: [endpointUrl('callback')],
  });
  logger.info('Client discovery complete. Configured.');
};

exports.clientVars = (hookName, context, callback) => {
  const {permit_displayname_change} = settings;
  return callback({[pluginName]: {permit_displayname_change}});
};

exports.expressCreateServer = (hookName, {app}) => {
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

exports.authenticate = (hookName, {req, res, users}, cb) => {
  logger.debug('authenticate hook for', req.url);
  const {session} = req;
  const {[pluginName]: {userinfo = {}} = {}} = session;
  const {sub} = userinfo;
  if (sub == null) {
    // Out of an abundance of caution, clear out the old state, nonce, and userinfo (if present) to
    // force regeneration.
    delete session[pluginName];
    // Authn failed. Let another plugin try to authenticate the user.
    return cb([]);
  }
  // Successfully authenticated.
  if (users[sub] == null) users[sub] = {};
  session.user = users[sub];
  session.user.username = sub;
  session.user.name = userinfo[settings.displayname_claim] || session.user.name;
  return cb([true]);
};

exports.authnFailure = (hookName, {req, res}, cb) => {
  const url = new URL(req.url.substr(1), settings.base_url).toString();
  res.redirect(`${endpointUrl('login')}?redirect_uri=${encodeURIComponent(url)}`);
  return cb([true]);
};

exports.handleMessage = async (hookName, {message, client}) => {
  logger.debug('handleMessage hook', message);
  const {user: {name} = {}} = client.client.request.session;
  if (!name) return;
  if (message.type == 'CLIENT_READY') {
    logger.debug(
      `CLIENT_READY ${client.id}: Setting username for token ${message.token} to ${name}`
    );
    // TODO: author ID might come from session ID, not token.
    const authorId = await authorManager.getAuthor4Token(message.token);
    await authorManager.setAuthorName(authorId, name);
  } else if (message.type == 'COLLABROOM' && message.data.type == 'USERINFO_UPDATE') {
    if (message.data.userInfo.name != name && !settings.permit_displayname_change) {
      message.data.userInfo.name = name;
    }
  }
};

exports.preAuthorize = (hookName, {req}, cb) => {
  if (req.path.startsWith(ep(''))) return cb([true]);
  return cb([]);
};
