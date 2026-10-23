# Working on this repo

`index.html` is the app, encrypted (AES-GCM, PBKDF2 key from username + password). The readable
source is never committed.

To make changes:
1. Ask the user for the app password (never write it into any file, commit, or message).
2. `WA_PASS='<password>' node tools/crypt.mjs unlock` → creates `index.src.html` (git-ignored).
3. Edit `index.src.html`, test it, then `WA_PASS='<password>' node tools/crypt.mjs lock`.
4. Commit only `index.html` (and tools/ if changed). Never commit `index.src.html`.
