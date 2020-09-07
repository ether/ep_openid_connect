'use strict';

/* global exports, require */

const log4js = require('ep_etherpad-lite/node_modules/log4js');
const {URL} = require('url');
const {Issuer, generators} = require('openid-client');
const authorManager = require('ep_etherpad-lite/node/db/AuthorManager');

const pluginName = 'ep_openid_connect';
const logger = log4js.getLogger(pluginName);
const settings = {};
let oidc_client = null;

const endpointUrl = (endpoint) => new URL(`auth/${endpoint}`, settings.base_url).toString();

async function createClient() {
  const issuer = await Issuer.discover(settings.issuer);
  const {client_id, client_secret, response_types} = settings;
  const redirect_uris = [endpointUrl('callback')];
  oidc_client = new issuer.Client({
    client_id,
    client_secret,
    response_types,
    redirect_uris,
  });
  logger.info('Client discovery complete. Configured.');
}

function authCallback(req, res, next) {
  logger.debug('Processing auth callback');
  (async () => {
    const params = oidc_client.callbackParams(req);
    const oidc_session = req.session[pluginName] || {};
    const {authParams} = oidc_session;
    if (authParams == null) throw new Error('no authentication paramters found in session state');
    const tokenset = await oidc_client.callback(endpointUrl('callback'), params, authParams);
    oidc_session.userinfo = await oidc_client.userinfo(tokenset);
    // The user has successfully authenticated, but don't set req.session.user here -- do it in the
    // authenticate hook so that Etherpad can log the authentication success. However, DO "log out"
    // the previous user to force the authenticate hook to run in case the user was already
    // authenticated as someone else.
    delete req.session.user;
    res.redirect(oidc_session.next || settings.base_url);
    // Defer deletion of state until success so that the user can reload the page to retry after a
    // transient backchannel failure.
    delete oidc_session.authParams;
    delete oidc_session.next;
  })().catch(next);
}

async function setUsername(token, username) {
  logger.debug('Setting author name for token', token);
  const author = await authorManager.getAuthor4Token(token);
  authorManager.setAuthorName(author, username);
}

exports.loadSettings = (hook_name, {settings: globalSettings}) => {
  const my_settings = globalSettings[pluginName];

  if (!my_settings) logger.error(`Expecting an ${pluginName} block in settings.`);
  for (const setting of ['base_url', 'client_id', 'client_secret', 'issuer']) {
    if (!my_settings[setting]) logger.error(`Expecting an ${pluginName}.${setting} setting.`);
  }
  Object.assign(settings, my_settings);
  // Make sure base_url ends with '/' so that relative URLs are appended:
  if (!settings.base_url.endsWith('/')) settings.base_url += '/';
  settings.displayname_claim = settings.displayname_claim || 'name';
  settings.response_types = settings.response_types || ['code'];
  settings.permit_displayname_change = settings.permit_displayname_change || false;
  createClient();
};

exports.clientVars = (hook_name, context, callback) => {
  const {permit_displayname_change} = settings;
  return callback({[pluginName]: {permit_displayname_change}});
};

exports.expressCreateServer = (hook_name, {app}) => {
  logger.debug('Configuring auth routes');
  app.get('/auth/callback', authCallback);
  app.get('/auth/failure', (req, res) => res.send('<em>Authentication Failed</em>'));
  app.get('/auth/login', (req, res, next) => {
    logger.debug('Processing /auth/login request');
    if (req.session[pluginName] == null) req.session[pluginName] = {};
    const oidc_session = req.session[pluginName];
    oidc_session.next = req.query.redirect_uri || settings.base_url;
    oidc_session.authParams = {nonce: generators.nonce(), state: generators.state()};
    res.redirect(oidc_client.authorizationUrl(oidc_session.authParams));
  });
  app.get('/logout', (req, res) => req.session.destroy(() => res.redirect(settings.base_url)));
};

exports.authenticate = (hook_name, {req, res, users}, cb) => {
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

exports.handleMessage = async (hook_name, {message, client}) => {
  logger.debug('handleMessage hook', message);

  const approve = [message];
  const deny = [null];

  const {session} = client.client.request;
  let name;
  if ('user' in session && session.user.name) name = session.user.name;

  if (name) {
    if (message.type == 'CLIENT_READY') {
      logger.debug(
        `CLIENT_READY ${client.id}: Setting username for token ${message.token} to ${name}`
      );
      await setUsername(message.token, name);
      return approve;
    } else if (message.type == 'COLLABROOM' && message.data.type == 'USERINFO_UPDATE') {
      if (message.data.userInfo.name != name && !settings.permit_displayname_change) {
        logger.info('Rejecting name change');
        return deny;
      }
    }
  }
  return approve;
};

exports.preAuthorize = (hook_name, {req}, cb) => {
  if (req.path.startsWith('/auth/')) return cb([true]);
  return cb([]);
};
