'use strict';

/* global $, clientVars, exports */

/* etherpad-lite uses uglify 2.x, so stick to ES5 */

exports.postToolbarInit = function () {
  if (!clientVars.ep_openid_connect.permit_displayname_change) {
    $('#myusernameedit').attr('disabled', true);
  }
};
