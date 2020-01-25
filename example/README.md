# Shellicator Examples

## Authorization Grant Flow Example
This is the more explicit example and uses the authorization grant flow to obtain an access & refresh token.

To run this example you need to setup the google identity platform. Use to following environment variables to configure the example:
```bash
export SHELLICATOR_CLIENT_ID=<client id provided by your iam>
export SHELLICATOR_CLIENT_SECRET=<client secret provided by your iam>
```

## Device Grant Flow Example
This example shows how to use the device grant type and the use of an _OpenIDConnect Discovery Endpoint_ to obtain an access & refresh token.

To run this example you need an identity provider that supports the device grant flow and provides an _Discovery Endpoint_. Use to following environment variables to configure the example:
```bash
export SHELLICATOR_CLIENT_ID=<client id provided by your iam>
export SHELLICATOR_OIDC_DISCOVERY=<discover enpoint of your iam provider>
export SHELLICATOR_USERPROFILE_URL=<url to the profile endpoint>
```