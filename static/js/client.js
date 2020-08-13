'use strict';
/*global clientVars:readonly, $:readonly*/

/* etherpad-lite uses uglify 2.x, so stick to ES5 */

exports.postToolbarInit = function() {
  var oidc_settings = clientVars['ep_openid-client'];
  var permit_author_name_change = oidc_settings.permit_author_name_change;
  if (!permit_author_name_change) {
    $('#myusernameedit').attr('disabled', true);
  }
};
