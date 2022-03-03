![Publish Status](https://github.com/ether/ep_openid_connect/workflows/Node.js%20Package/badge.svg) ![Backend Tests Status](https://github.com/ether/ep_openid_connect/workflows/Backend%20tests/badge.svg)

# ep\_openid\_connect

Etherpad plugin to authenticate users against an OpenID Connect provider.

It uses provider discovery to keep configuration simple.

Unlike other auth plugins, this one is not based around passport, for
simplicity.

This is a fork of
[ep\_openid-client](https://github.com/stefanor/ep_openid-client).

## Configuration

The plugin expects an `ep_openid_connect` block in the settings, with
this structure:

```json
  "ep_openid_connect": {
    "issuer": "https://id.example.com",
    "client_id": "MY CLIENT ID",
    "client_secret": "MY CLIENT SECRET",
    "base_url": "https://pad.example.com"
  },
  "requireAuthentication": true,
```

OAuth/OpenID Connect redirect URL (a.k.a. callback URL):
`https://pad.example.com/ep_openid_connect/callback`

Etherpad's `requireAuthentication` setting must be `true`.

### Configuration Details

* `issuer` (required if `issuer_metadata` is not set): The base URL of the
  OpenID Connect identity provider, used to discover the relevant OpenID Connect
  endpoints. If set, your identity provider must support the [OpenID Connect
  Discovery](https://openid.net/specs/openid-connect-discovery-1_0.html)
  protocol.
* `issuer_metadata` (required if `issuer` is not set): Object containing details
  about your OpenID Connect identity provider. Used for manual configuration if
  your identity provider does not support the Discovery protocol. If your
  identity provider does support Discovery, you are encouraged to set `issuer`
  instead. For properties, see the [documentation for the openid-client `Issuer`
  object
  constructor](https://github.com/panva/node-openid-client/blob/v4.7.4/docs/README.md#new-issuermetadata).
* `client_id` (required): The OAuth2 client ID issued by the identity provider.
* `client_secret` (required): The OAuth2 client secret issued by the identity
  provider.
* `base_url` (required): The public base Etherpad URL. When registering Etherpad
  with your identity provider, the redirect URL (a.k.a. callback URL) is this
  base URL plus `/ep_openid_connect/callback`.
* `scope` (optional; defaults to `["openid"]`): List of OAuth2 scope strings.
* `prohibited_usernames` (optional; defaults to `["admin", "guest"]`): List of
  strings that will trigger an authentication error if any match the `sub`
  (subject) claim from the identity provider. Use this to avoid conflicts with
  the users in the `users` setting and to avoid conflicts with other plugins
  (such as [ep\_guest](https://github.com/ether/ep_guest#readme)).
* `user_properties` (optional): Object that controls the automatic creation of
  additional properties on each authenticated user's account object. See below
  for details.

## Interaction with the `users` Setting

When a user authenticates, the value of the `sub` (subject) claim is used as the
user's username in Etherpad. (The `sub` claim is the identity provider's unique
identifier for the user.) Many identity providers (such as GitLab) identify
users by a numeric user ID, so the `sub` claim (and thus the Etherpad username)
will probably look something like "5374".

Each authenticated user gets their own account object. Default properties for a
user's account object come from the `users` setting in `settings.json`. Etherpad
uses the `is_admin`, `readOnly`, and `canCreate` properties to control access,
and the
[ep\_user\_displayname](https://github.com/ether/ep_user_displayname#readme)
plugin uses the `displayname` property for the name displayed in the user list.
For example, the following sets the default display name to "Firstname Lastname"
and the default access to read-only for the user identified by "5374":

```json
  "users": {
    "5374": {
      "displayname": "Firstname Lastname",
      "readOnly": true
    }
  },
```

To avoid unintentionally applying values to users authenticated via this plugin,
you can use the `prohibited_usernames` settings to force an authentication error
if the `sub` claim happens to match. This is useful for preventing a malicious
identity provider from gaining admin access to your Etherpad instance.

### Controlling user account object properties with `user_properties`

The `user_properties` setting can be used to automatically add, remove, or
change properties on a user's account object when the user authenticates. The
`user_properties` setting maps a property name to a descriptor object that
describes how the property's value is obtained:

  * If the descriptor object has a `claim` property that names an existing
    OpenID Connect claim, the value is set to the value of the claim. (If there
    is no such claim, `claim` has no effect.)
  * If the descriptor object has a `default` property and the account object
    property would otherwise be unset, the property is set to the given value.
    (Note that a property set to `undefined` is not the same as unset.)
  * If the descriptor object is `null`, the property is removed if present.

Furthermore:

  * If `user_properties` does not specifiy a descriptor for `displayname`, one
    is added as follows:

    ```json
      "ep_openid_connect": {
        "user_properties": {
          "displayname": {"claim": "name"}
        }
      },
    ```

    You can cancel out this default behavior by explicitly specifying an empty
    object:

    ```json
      "ep_openid_connect": {
        "user_properties": {
          "displayname": {}
        }
      },
    ```

  * The `username` property is described as follows and cannot be overridden or
    canceled:

    ```json
      "ep_openid_connect": {
        "user_properties": {
          "username": {"claim": "sub"}
        }
      },
    ```

Example:

```json
  "ep_openid_connect": {
    "user_properties": {
      "fromClaimWithDefault": {
        "claim": "claimName",
        "default": "default value"
      },
      "fromClaimOrUnset": {
        "claim": "claimName"
      },
      "fixedValue": {
        "default": "fixed value"
      },
      "forcedUnset": null
    }
  },
```

The above example sets properties as follows:
* Each user's `fromClaimWithDefault` property is set to the value of the user's
  `claimName` claim if present, otherwise the property is left unchanged if
  already set, otherwise it is set to the string `"default value"`.
* Each user's `fromClaimOrUnset` property is set to the value of the user's
  `claimName` claim if present, otherwise the property is left unset/unchanged.
* Each user's `fixedValue` property is set to the string `"fixed value"`
  unless already set.
* Each user's `forcedUnset` property is always deleted if present.
* Each user's `displayname` property is set to to the value of the user's `name`
  claim if present, otherwise the property is left unset/unchanged.
* Each user's `username` property is set to the value of the `sub` claim.

You can use this feature to control access in the OpenID Connect provider if it
provides suitable claims:

```json
  "ep_openid_connect": {
    "scope": ["openid", "etherpad"],
    "user_properties": {
      "is_admin": {"claim": "etherpad_is_admin"},
      "readOnly": {"claim": "etherpad_readOnly"},
      "canCreate": {"claim": "etherpad_canCreate"}
    }
  },
```

To avoid breaking assumptions made by Etherpad, the `username` property cannot
be altered via the `user_properties` setting.

## Interaction with the ep\_guest Plugin

The [ep\_guest](https://github.com/ether/ep_guest#readme) plugin creates a user
that is used for all guest accesses. It is recommended you add the username you
chose for the guest user to the `prohibited_usernames` setting. If the identity
provider ever uses that username in the `sub` claim, you will get an obvious
error instead of a mysterious inability to edit pads.

## Interaction with the ep\_user\_displayname Plugin

By default, this plugin sets the user's `displayname` property to the value of
the `name` claim. The
[ep\_user\_displayname](https://github.com/ether/ep_user_displayname#readme)
plugin uses this property (and the `displaynameChangeable` property) to control
the name displayed in the pad's list of users.

You can change the claim used to get the displayname:

```json
  "ep_openid_connect": {
    "user_properties": {
      "displayname": {"claim": "nickname"}
    }
  },
```

Or you can cancel the default behavior:


```json
  "ep_openid_connect": {
    "user_properties": {
      "displayname": {}
    }
  },
```

## Interaction with Etherpad's Built-in HTTP Basic Authentication

If the user has not yet successfully authenticated, this plugin defers the
access decision—it does not explicitly deny access. This causes Etherpad to fall
back to another authentication plugin (if one is installed) or to the built-in
HTTP basic authentication.

Note: This plugin installs an authentication failure handler, so the user will
not get a 401 error that causes the browser to prompt for a username and
password for HTTP basic auth. To fall back to HTTP basic authentication, the
user's browser must proactively set the `Authorization: Basic <credentials>`
header.

## Interaction with Authorization Plugins

This plugin sets `req.session.user` to the user's settings object from
`settings.json` and sets `req.session.user.username` to the user's username (the
`sub` claim). Etherpad's built-in HTTP basic authentication does the same thing,
so any authorization plugin designed to work with Etherpad's built-in
authentication should work with this plugin.

## Support

Currently only tested against GitLab instances.

## Copyright and License

Copyright © 2020 Stefano Rivera <stefano@rivera.za.net>\
Copyright © 2020-2021 Richard Hansen <rhansen@rhansen.org>

Licensed under the [MIT/Expat license](LICENSE).

This is a fork of
[ep\_openid-client](https://github.com/stefanor/ep_openid-client) by Stefano
Rivera, which is based on
[ep\_oauth2](https://github.com/HumanBrainProject/ep_oauth2) and
[ep\_oidc](https://github.com/ToniIltanen/ep_oidc).
