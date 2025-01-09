[![CharmHub Badge](https://charmhub.io/digest-squid-auth-helper/badge.svg)](https://charmhub.io/digest-squid-auth-helper)
[![Promote charm](https://github.com/canonical/digest-squid-auth-helper/actions/workflows/promote_charm.yaml/badge.svg)](https://github.com/canonical/digest-squid-auth-helper/actions/workflows/promote_charm.yaml)

# Squid Proxy Htfile auth helper

## Description

A [Juju](https://juju.is/) subordinate [charm](https://juju.is/docs/olm/charmed-operators) for
the [Squid Reverseproxy charm](https://charmhub.io/squid-reverseproxy) that enables
digest or basic authentication using squid-auth-helper relation.

As a subordinate charm this charm requires the [Squid Reverseproxy charm](https://charmhub.io/squid-reverseproxy)
to be deployed and integrated with it.

The charm brings digest or basic authentication support to the Squid Reverseproxy using the `squid-auth-helper` charm relation.
It allows you to manage user credentials through charm actions (create-user, remove-user, list-users), and configure authentication
parameters using charm configuration.

While the Squid Reverseproxy charm targets a "reverse proxy setup".
This subordinate charm is currently only tested for a "forward proxy" use case.

## Get started

### Set up

If you don't already have a running Juju environment, you can follow the [Get started with Juju](https://juju.is/docs/juju/tutorial) guide to set up an isolated test environment.

As this charm is a subordinate charm, you should have a [Squid Reverseproxy charm](https://charmhub.io/squid-reverseproxy) running before deploying it.

- Create your juju model: `juju add-model test-squid`
- Deploy the reverseproxy charm: `juju deploy squid-reverseproxy`
- Monitor the deployment with: `juju status --watch 2s`

**Important**: for the authentification to be triggered, you need to set up ACL and disable vhost acceleration. You can do so with the following command: `juju config squid-reverseproxy auth_list='- "proxy_auth": [REQUIRED]' port_options=""`.

### Deploy

Once your Squid instance is running, deploy the auth helper charm with `juju deploy digest-squid-auth-helper` and integrate it with your reverse proxy with `juju integrate squid-reverseproxy digest-squid-auth-helper`.

### Basic operations

#### Configure the authentication type

The default configuration can be seen using the `juju config digest-squid-auth-helper` command.

The default authentication type is "digest". If you want to switch to Basic authentication, you can issue the `juju config digest-squid-auth-helper authentication-type=basic` command.

Warning: changing the authentication type will reset all existing users.

#### Giving access to users

New users can be given access through the `juju run digest-squid-auth-helper/0 create-user username=yourusername`. The command will return you the username, realm and password.

#### Listing current users

The `juju run digest-squid-auth-helper/0 list-users` will return the list of active users.

#### Removing users

You can remove users with `juju run digest-squid-auth-helper/0 remove-user username=yourusername`

Note: Squid caches some authentication lookups (see [documentation](https://wiki.squid-cache.org/Features/Authentication#does-squid-cache-authentication-lookups)).

## Project and community

The digest-squid-auth-helper subordinate charm is a member of the Ubuntu family. It's an
open source project that warmly welcomes community projects, contributions,
suggestions, fixes and constructive feedback.
* [Issues](https://github.com/canonical/digest-squid-auth-helper/issues)
* [Get support](https://discourse.charmhub.io/)
* [Contribute](https://charmhub.io/digest-squid-auth-helper/docs/contributing)
