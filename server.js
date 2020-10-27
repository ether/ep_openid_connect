'use strict';

const {URL} = require('url');
const {Issuer, generators} = require('openid-client');
const authorManager = require('ep_etherpad-lite/node/db/AuthorManager');

const oidc_settings = {};
let oidc_client = null;

function redirectURL() {
  return new URL('/auth/callback', oidc_settings.base_url).toString();
}

async function createClient() {
  const issuer = await Issuer.discover(oidc_settings.issuer);
  const {client_id, client_secret, response_types} = oidc_settings;
  const redirect_uris = [redirectURL()];
  oidc_client = new issuer.Client({
    client_id,
    client_secret,
    response_types,
    redirect_uris,
  });
  console.info('ep_openid-client: Client discovery complete. Configured.');
}

async function authCallback(req, res) {
  console.debug('ep_openid-client: Processing auth callback');

  const params = oidc_client.callbackParams(req);
  const {session} = req;
  const oidc_session = req.session['ep_openid-client'] || {};
  const {nonce, state} = oidc_session;
  delete oidc_session.nonce;
  delete oidc_session.state;
  let tokenset;
  try {
    tokenset = await oidc_client.callback(redirectURL(), params, {nonce, state});
  } catch (e) {
    console.log('Authentication failed', e);
    return res.send('Authentication failed');
  }

  const userinfo = await oidc_client.userinfo(tokenset);
  const sub = userinfo.sub;
  const user_name = userinfo[oidc_settings.author_name_key];
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
  console.debug('ep_openid-client: Setting author name for token', token);
  const author = await authorManager.getAuthor4Token(token);
  authorManager.setAuthorName(author, username);
}

exports.loadSettings = (hook_name, {settings}) => {
  const my_settings = settings['ep_openid-client'];

  if (!my_settings) {
    console.error('ep_openid-client: Expecting a ep_openid-client block in settings.');
  }
  for (const setting of ['base_url', 'client_id', 'client_secret', 'issuer', 'author_name_key']) {
    if (!my_settings[setting]) {
      console.error('ep_openid-client: Expecting a ep_openid-client.' + setting + ' setting.');
    }
  }
  Object.assign(oidc_settings, my_settings);
  oidc_settings.response_types = oidc_settings.response_types || ['code'];
  oidc_settings.permit_author_name_change = oidc_settings.permit_author_name_change || false;
  oidc_settings.permit_anonymous_read_only = oidc_settings.permit_anonymous_read_only || false;
  createClient();
};

exports.clientVars = (hook_name, context, callback) => {
  const {permit_author_name_change} = oidc_settings;
  return callback({'ep_openid-client': {permit_author_name_change}});
};

exports.expressCreateServer = (hook_name, {app}) => {
  console.debug('ep_openid-client: Configuring auth routes');
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
  console.debug('ep_openid-client: authenticate hook for', req.url);
  if (!req.session['ep_openid-client']) req.session['ep_openid-client'] = {};
  const session = req.session['ep_openid-client'];

  if (session.sub || req.path.startsWith('/auth/')) return next();
  if (oidc_settings.permit_anonymous_read_only) {
    if (req.path.match(/^\/(locales\.json|(p\/r\.|socket.io\/).*)$/)) return next();
  }
  session.next = req.url;
  session.nonce = generators.nonce();
  session.state = generators.state();
  return res.redirect(oidc_client.authorizationUrl({nonce: session.nonce, state: session.state}));
};

exports.handleMessage = (hook_name, {message, client}, cb) => {
  console.debug('ep_openid-client: handleMessage hook', message);

  const approve = () => cb([message]);
  const deny = () => cb([null]);

  const {session} = client.client.request;
  let name;
  if ('user' in session && session.user.name) name = session.user.name;

  if (name) {
    if (message.type == 'CLIENT_READY') {
      console.debug(
        'ep_openid-client: CLIENT_READY %s: Setting username for token %s to %s',
        client.id,
        message.token,
        name
      );
      setUsername(message.token, name).finally(approve);
      return;
    } else if (message.type == 'COLLABROOM' && message.data.type == 'USERINFO_UPDATE') {
      if (message.data.userInfo.name != name && !oidc_settings.permit_author_name_change) {
        console.info('ep_openid-client: Rejecting name change');
        return deny();
      }
    }
  }
  return approve();
};
