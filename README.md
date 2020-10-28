# ep\_openid\_connect

Etherpad plugin to authenticate users against an OpenID Connect provider.

It uses provider discovery to keep configuration simple.

Unlike other auth plugins, this one is not based around passport, for
simplicity.

This is a fork of
[ep\_openid-client](https://github.com/stefanor/ep_openid-client).

## Settings

The plugin expects an `ep_openid_connect` block in the settings, with
this structure:

```json
  "ep_openid_connect": {
    "issuer": "https://id.example.com",
    "client_id": "MY CLIENT ID",
    "client_secret": "MY CLIENT SECRET",
    "base_url": "https://pad.example.com"
  },
```

### Settings Details

* `issuer` (required): The base URL of the OpenID Connect identity provider,
  used to perform discovery of the endpoints.
* `client_id` (required): The OAuth2 client ID issued by the identity provider.
* `client_secret` (required): The OAuth2 client secret issued by the identity
  provider.
* `base_url` (required): The public base Etherpad URL.
* `author_name_key` (optional; defaults to `"name"`): The claim containing the
  name to display in the pad's user list.
* `response_types` (optional; defaults to `["code"]`): List of OpenID Connect
  response types.
* `permit_author_name_change` (optional; defaults to `false`): Whether users may
  change their displayed name.

## Support

Currently only tested against GitLab instances.

## Copyright and License

Copyright © 2020 Stefano Rivera <stefano@rivera.za.net>
Copyright © 2020 Richard Hansen <rhansen@rhansen.org>

Licensed under the [MIT/Expat license](LICENSE).

This is a fork of
[ep\_openid-client](https://github.com/stefanor/ep_openid-client) by Stefano
Rivera, which is based on
[ep\_oauth2](https://github.com/HumanBrainProject/ep_oauth2) and
[ep\_oidc](https://github.com/ToniIltanen/ep_oidc).
