# Changelog

## Unreleased

#### Behaviour changes

  * `token_endpoint_auth_method` now defaults to auto-detection from the
    identity provider's discovery document. The plugin prefers
    `client_secret_post` when advertised and falls back to
    `client_secret_basic`. This fixes silent token-endpoint
    `WWWAuthenticateChallengeError` failures on GitLab.com (which advertises
    both methods but rejects `client_secret_basic`). Users who previously
    relied on the `client_secret_basic` default without setting it explicitly
    may now exchange tokens via `client_secret_post`; set the option
    explicitly to pin a specific method.

## v3.0.0

Released 2022-03-04.

#### Compatibility changes

  * Removed the deprecated `displayname_claim` setting. Set
    `user_properties.displayname.claim` instead.
  * Displayname rendering was moved to the
    [ep\_user\_displayname](https://github.com/ether/ep_user_displayname#readme)
    plugin and the `permit_displayname_change` setting was removed.
  * The plugin is now much more strict about what it accepts as valid settings.
