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

function authCallback(req, res, next) {
  logger.debug('Processing auth callback');
  (async () => {
    const params = oidc_client.callbackParams(req);
    const {session} = req;
    const oidc_session = session[pluginName] || {};
    const {authParams} = oidc_session;
    if (authParams == null) throw new Error('no authentication paramters found in session state');
    const tokenset = await oidc_client.callback(redirectURL(), params, authParams);

    const userinfo = await oidc_client.userinfo(tokenset);
    const sub = userinfo.sub;
    const user_name = userinfo[settings.displayname_claim];
    oidc_session.sub = sub;
    session.user = {
      name: user_name,
      is_admin: false,
    };

    res.redirect(oidc_session.next || '/');
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
  app.get('/logout', (req, res) => req.session.destroy(() => res.redirect(settings.base_url)));
};

exports.authenticate = (hook_name, {req, res, next}) => {
  logger.debug('authenticate hook for', req.url);
  if (!req.session[pluginName]) req.session[pluginName] = {};
  const session = req.session[pluginName];

  if (session.sub || req.path.startsWith('/auth/')) return next();
  session.next = req.url;
  session.authParams = {nonce: generators.nonce(), state: generators.state()};
  return res.redirect(oidc_client.authorizationUrl(session.authParams));
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
      if (message.data.userInfo.name != name && !settings.permit_displayname_change) {
        logger.info('Rejecting name change');
        return deny();
      }
    }
  }
  return approve();
};
