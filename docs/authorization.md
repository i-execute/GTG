# Authorization

`auth` stores bot tokens and imported user sessions only in the encrypted vault. A loaded bot token remains a `vault.Secret` until the caller reads and destroys it. Callers must destroy decoded session material when it is no longer required.
