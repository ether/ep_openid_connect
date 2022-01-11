'use strict';

const assert = require('assert').strict;
const common = require('ep_etherpad-lite/tests/backend/common');

const logger = common.logger;

const followRedirects = async (agent, res) => {
  if (res.status !== 303) return res;
  const url = new URL(res.headers.location, res.request.url);
  logger.debug(`redirected to ${url}`);
  return await followRedirects(agent, await agent.get(url));
};

// There might not be a set-cookie header on the response if the request sent a cookie and the
// cookie value hasn't changed. If there is no set-cookie header, use the request's cookie.
const fakeSetCookie = (jar, res) => {
  if (!res.headers['set-cookie']) {
    const url = new URL(res.request.url);
    const cookies = jar.getCookies({
      domain: url.hostname, // No port.
      path: url.pathname,
      secure: url.protocl === 'https:',
      script: false,
    }).toString();
    if (cookies) res.headers['set-cookie'] = cookies;
  }
  return res;
};

module.exports = async (agent, issuer, startUrl, username) => {
  // Visit the start URL and follow the redirects to the login page.
  let res = await followRedirects(agent, await agent.get(startUrl));
  const wantUrlBase = new URL('/interaction/', issuer).toString();
  assert(res.request.url.startsWith(wantUrlBase),
      `expected ${res.request.url} to start with ${wantUrlBase}`);
  assert.equal(res.status, 200);

  // Log in and follow redirects to the consent page.
  logger.debug(`submitting login=${username}`);
  res = await followRedirects(agent, await agent.get(`${res.request.url}?login=${username}`));
  if (!res.request.url.startsWith(new URL('/interaction/', issuer).toString())) {
    logger.debug('did not redirect to the consent page');
    return fakeSetCookie(agent.jar, res);
  }
  assert.equal(res.status, 200);

  // Indicate consent and follow redirects. (It should redirect back to the original URL, but that
  // verification is done by the caller so that this function can be used to test error cases.)
  logger.debug('submitting consent=true');
  res = await followRedirects(agent, await agent.get(`${res.request.url}?consent=true`));
  return fakeSetCookie(agent.jar, res);
};
