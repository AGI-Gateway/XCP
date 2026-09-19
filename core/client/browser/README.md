# XCP Browser Client

A single-file demo client. Open `index.html` against a running gateway.

Browsers can't present an mTLS client certificate from JavaScript, so a browser
agent uses a **delegated-session model**: a trusted local service (or platform
credential helper) holds the certificate and the page drives it over a local
channel. This demo derives a development footprint from the agent id, which the
reference gateway's local registry accepts, so you can exercise the full
session → tool-call flow in the browser.
