'use strict';

exports.postToolbarInit = () => {
  if (!clientVars.ep_openid_connect.permit_displayname_change) {
    $('#myusernameedit').attr('disabled', true);
  }
};
