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
* `displayname_claim` (optional; defaults to `"name"`): The claim containing the
  name to display in the pad's user list.
* `response_types` (optional; defaults to `["code"]`): List of OpenID Connect
  response types.
* `permit_displayname_change` (optional; defaults to `false`): Whether users may
  change their displayed name.
* `prohibited_usernames` (optional; defaults to `['admin', 'guest']`): List of
  strings that will trigger an authentication error if any match the `sub`
  (subject) claim from the identity provider. Use this to avoid conflicts with
  the users in the `users` setting and to avoid conflicts with other plugins
  (such as
  [ep\_readonly\_guest](https://github.com/ether/ep_readonly_guest#readme)).

## Interaction with the `users` Setting

When a user authenticates, the value of the `sub` (subject) claim is used as the
user's username in Etherpad. (The `sub` claim is the identity provider's unique
identifier for the user.) Many identity providers (such as GitLab) identify
users by a numeric user ID, so the `sub` claim (and thus the Etherpad username)
will probably look something like "5374".

All values associated with that username in the `settings.json` `users` object
are applied to the user, including `is_admin`, `readOnly`, and `canCreate`.

For example, if you want the user identified by "5374" to be a read-only user,
you would add the following to your `settings.json`:

```json
  "users": {
    "5374": {
      "readOnly": true
    }
  },
```

To avoid unintentionally applying values to users authenticated via this plugin,
you can use the `prohibited_usernames` settings to force an authentication error
if the `sub` claim happens to match. This is useful for preventing a malicious
identity provider from gaining admin access to your Etherpad instance.

## Interaction with the ep\_readonly\_guest Plugin

The [ep\_readonly\_guest
plugin](https://github.com/ether/ep_readonly_guest#readme) creates a user that
is used for all guest accesses. It is recommended you add the username you chose
for the guest user to the `prohibited_usernames` setting. If the identity
provider ever uses that username in the `sub` claim, you will get an obvious
error instead of a mysterious inability to edit pads.

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
