Instance Identity plugin for Jenkins
====================================

This plugin maintains an RSA key pair that can serve
as a foundation of authentication when communicating with Jenkins.

## Description

Each Jenkins instance maintains an RSA private/public key pair
that can be used to uniquely identify Jenkins.
This information is called "instance identity".

From outside, the public key can be obtained by sending the GET request
to the top page of Jenkins,
and look for the _X-Instance-Identity_ header in the response.
This header is always available, even if the response is 401 access denied
(which can happen if Jenkins is protected via security.)
The value represents a base64-encoded ASN.1 DER serialization of X.509 SubjectPublicKeyInfo record.

Plugins that run inside Jenkins can access this key pair programmatically through
the `org.jenkinsci.main.modules.instance_identity.InstanceIdentity` class
(add a plugin-to-plugin dependency on this plugin into your plugin).

## Possible use

* Sometimes, a Jenkins server is accessible through multiple URLs.
  This ID can be used to identify duplicates in those.
* Plugins can use the private key to produce a digital signature of some data
  that can be verified later by other parties about its origin.

## License

[MIT License](https://opensource.org/licenses/mit-license.php)

## Changelog

Current: [GitHub Releases](https://github.com/jenkinsci/instance-identity-plugin/releases)

[Archives](https://github.com/jenkinsci/instance-identity-plugin/blob/34be923381d81ce7cec72fc6d6a70b07d84d46f0/CHANGELOG.md)
