# Security

This application accepts text from devices on the local network and injects it
into Windows input targets. Treat every device that has the current pairing URL
as trusted.

## Safe use

- Use the access token unless the network is fully trusted.
- Do not expose the listening port directly to the public internet.
- Regenerate the connection code if its URL or token may have leaked.
- Keep Windows Firewall limited to private networks where possible.
- Run the tool with the same privilege level as the target application.

The project does not intentionally persist dictated text or error-log text.
Local runtime files such as `.phone_voice_token`,
`.phone_voice_settings.json`, and generated QR images are excluded from Git.

## Reporting a vulnerability

Please use the repository's private GitHub Security Advisory reporting feature
when available. Avoid posting undisclosed security vulnerabilities, pairing
tokens, private IP addresses, or dictated text in a public issue.