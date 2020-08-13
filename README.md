# ep_openid-client

An Open ID Connect auth plugin for etherpad-lite.

It uses provider discovery to keep configuration simple.

Unlike other auth plugins, this one is not based around passport, for
simplicity.

## Settings

The plugin expects an `ep_openid-client` block in the settings, with
this structure:

```json
  "ep_openid-client": {
    "issuer": "https://id.exmaple.com",
    "client_id": "MY CLINENT ID",
    "client_secret": "MY CLIENT SECRET",
    "base_url": "https://pad.example.com",
    "author_name_key": "name",
    "permit_author_name_change": false,
    "permit_anonymous_read_only": false,
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
* `permit_anonymous_read_only`: Optional Boolean. If true, anonymous
                                users may view the pad.

## Support

Currently only tested against GitLab instances.

## License

Licensed under the [MIT/Expat license](LICENSE).
Based on [ep_oauth2] and [ep_oidc].

[ep_oauth2]: https://github.com/HumanBrainProject/ep_oauth2
[ep_oidc]: https://github.com/ToniIltanen/ep_oidc
