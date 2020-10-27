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
    "issuer": "https://id.exmaple.com",
    "client_id": "MY CLINENT ID",
    "client_secret": "MY CLIENT SECRET",
    "base_url": "https://pad.example.com",
    "author_name_key": "name",
    "permit_author_name_change": false
  },
```

### Settings Details

* `issuer`: The base URL of the Open ID Connect instance, used to
            perform discovery of the endpoints.
* `client_id`: The OAUTH2 client ID issued by the server.
* `client_secret`: The OAUTH2 client secret issued by the server.
* `base_url`: The public base URL of the Etherpad install.
* `author_name_key`: The key into the userinfo structure, that will
                     return the desired name for the authors.
* `response_types`: Optional list of OpenID Connect response types.
                    Defualts to `["code"]`.
* `permit_author_name_change`: Optional Boolean. If true, authors may
                               change their display name.

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
