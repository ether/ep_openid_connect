# Changelog

## v3.0.0

Released 2022-03-04.

#### Compatibility changes

  * Removed the deprecated `displayname_claim` setting. Set
    `user_properties.displayname.claim` instead.
  * Displayname rendering was moved to the
    [ep\_user\_displayname](https://github.com/ether/ep_user_displayname#readme)
    plugin and the `permit_displayname_change` setting was removed.
  * The plugin is now much more strict about what it accepts as valid settings.
