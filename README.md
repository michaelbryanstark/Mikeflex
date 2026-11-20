# Mikeflex

    pip install -r requirements.txt
    python netflix_app.py          # then open http://127.0.0.1:5000

Back up `team_netflix.db` first: on start-up the app adds `account.is_admin`,
`film.poster` and `tv_show.poster`, and (if there is no admin yet) creates
`admin@teamnetflix.com` with a random password printed in the terminal.

- Customer site: `/login`, `/signup`, `/profiles`, `/browse`, `/search`, `/title/...`, `/my-list`, `/account`
- Admin dashboard: `/admin` (accounts with `is_admin = 1` only)
- Make an existing account an admin: `python netflix_app.py make-admin someone@example.com`
- Reset a password: `python netflix_app.py set-password someone@example.com`
- Real posters (optional): `TMDB_API_KEY=... python fetch_posters.py`
- Uploaded pictures are stored in `uploads/` next to the script.
- Old plain-text passwords from the seed data keep working and are converted
  to hashes the first time each account signs in.
