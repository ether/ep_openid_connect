'use strict';

exports.postToolbarInit = () => {
  const {ep_openid_connect: {permit_displayname_change = true} = {}} = clientVars;
  if (!permit_displayname_change) $('#myusernameedit').attr('disabled', true);
};
