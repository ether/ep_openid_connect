'use strict';

/* global $, clientVars, exports */

exports.postToolbarInit = () => {
  if (!clientVars.ep_openid_connect.permit_displayname_change) {
    $('#myusernameedit').attr('disabled', true);
  }
};
