'use strict';

/* global $, clientVars, exports */

/* etherpad-lite uses uglify 2.x, so stick to ES5 */

exports.postToolbarInit = function () {
  var settings = clientVars.ep_openid_connect;
  var permit_author_name_change = settings.permit_author_name_change;
  if (!permit_author_name_change) {
    $('#myusernameedit').attr('disabled', true);
  }
};
