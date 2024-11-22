[![CharmHub Badge](TODO)](TODO)
[![Promote charm](https://github.com/canonical/htfile-squid-auth-helper/actions/workflows/promote_charm.yaml/badge.svg)](https://github.com/canonical/htfile-squid-auth-helper/actions/workflows/promote_charm.yaml)
[![Discourse Status](https://img.shields.io/discourse/status?server=https%3A%2F%2Fdiscourse.charmhub.io&style=flat&label=CharmHub%20Discourse)](https://discourse.charmhub.io)

# Squid Proxy Htfile auth helper

## Description

A [Juju](https://juju.is/) subordinate [charm](https://juju.is/docs/olm/charmed-operators) for
the [Squid Reverseproxy charm](https://charmhub.io/squid-reverseproxy) that allows
authentication digest or basic authentication using squid-auth-helper relation.

As a subordinate charm this charm requires the [Squid Reverseproxy charm](https://charmhub.io/squid-reverseproxy)
to be deployed and integrated with it.

The charm brings digest or basic authentication support to the Squid Reverseproxy using the `squd-auth-helper` charm relation.
It allows you to manage user credentials through charm actions (create-user, remove-user, list-users), and configure authentication
parameters using charm configuration

## Project and community

The squid-auth-local subordinate charm is a member of the Ubuntu family. It's an
open source project that warmly welcomes community projects, contributions,
suggestions, fixes and constructive feedback.
* [Code of conduct](https://ubuntu.com/community/code-of-conduct)
* [Get support](https://discourse.charmhub.io/)
* [Join our online chat](https://chat.charmhub.io/squid-auth-local/channels/charm-dev)
* [Contribute](https://charmhub.io/squid-auth-local/docs/contributing)
* [Roadmap](https://charmhub.io/squid-auth-local/docs/roadmap)
Thinking about using the squid-auth-local charm for your next project? [Get in touch](https://chat.charmhub.io/charmhub/channels/charm-dev)!

