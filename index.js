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

function redirectURL() {
  return new URL('/auth/callback', settings.base_url).toString();
}

async function createClient() {
  const issuer = await Issuer.discover(settings.issuer);
  const {client_id, client_secret, response_types} = settings;
  const redirect_uris = [redirectURL()];
  oidc_client = new issuer.Client({
    client_id,
    client_secret,
    response_types,
    redirect_uris,
  });
  logger.info('Client discovery complete. Configured.');
}

async function authCallback(req, res) {
  logger.debug('Processing auth callback');

  const params = oidc_client.callbackParams(req);
  const {session} = req;
  const oidc_session = req.session[pluginName] || {};
  const {nonce, state} = oidc_session;
  delete oidc_session.nonce;
  delete oidc_session.state;
  let tokenset;
  try {
    tokenset = await oidc_client.callback(redirectURL(), params, {nonce, state});
  } catch (e) {
    logger.log('Authentication failed', e);
    return res.send('Authentication failed');
  }

  const userinfo = await oidc_client.userinfo(tokenset);
  const sub = userinfo.sub;
  const user_name = userinfo[settings.author_name_key];
  oidc_session.sub = sub;
  session.user = {
    name: user_name,
    is_admin: false,
  };

  authorManager.createAuthorIfNotExistsFor(sub, user_name);
  res.redirect(oidc_session.next || '/');
  delete oidc_session.next;
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
  settings.author_name_key = settings.author_name_key || 'name';
  settings.response_types = settings.response_types || ['code'];
  settings.permit_author_name_change = settings.permit_author_name_change || false;
  createClient();
};

exports.clientVars = (hook_name, context, callback) => {
  const {permit_author_name_change} = settings;
  return callback({[pluginName]: {permit_author_name_change}});
};

exports.expressCreateServer = (hook_name, {app}) => {
  logger.debug('Configuring auth routes');
  app.get('/logout', (req, res) =>
    req.session.destroy(() => {
      req.logout();
      res.redirect('/');
    })
  );
  app.get('/auth/callback', authCallback);
  app.get('/auth/failure', (req, res) => res.send('<em>Authentication Failed</em>'));
};

exports.authenticate = (hook_name, {req, res, next}) => {
  logger.debug('authenticate hook for', req.url);
  if (!req.session[pluginName]) req.session[pluginName] = {};
  const session = req.session[pluginName];

  if (session.sub || req.path.startsWith('/auth/')) return next();
  session.next = req.url;
  session.nonce = generators.nonce();
  session.state = generators.state();
  return res.redirect(oidc_client.authorizationUrl({nonce: session.nonce, state: session.state}));
};

exports.handleMessage = (hook_name, {message, client}, cb) => {
  logger.debug('handleMessage hook', message);

  const approve = () => cb([message]);
  const deny = () => cb([null]);

  const {session} = client.client.request;
  let name;
  if ('user' in session && session.user.name) name = session.user.name;

  if (name) {
    if (message.type == 'CLIENT_READY') {
      logger.debug(
        `CLIENT_READY ${client.id}: Setting username for token ${message.token} to ${name}`
      );
      setUsername(message.token, name).finally(approve);
      return;
    } else if (message.type == 'COLLABROOM' && message.data.type == 'USERINFO_UPDATE') {
      if (message.data.userInfo.name != name && !settings.permit_author_name_change) {
        logger.info('Rejecting name change');
        return deny();
      }
    }
  }
  return approve();
};
