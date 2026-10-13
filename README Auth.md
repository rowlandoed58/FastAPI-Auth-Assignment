# FastAPI Authentication Assignment

A FastAPI app with JWT authentication, role-based access (admin / editor / user),
and a notes API. Built with SQLite and SQLAlchemy. Passwords are hashed with passlib.

## Run it

```
python -m venv venv
venv\Scripts\activate          # Windows
source venv/bin/activate       # Mac / Linux

pip install -r requirements.txt
uvicorn main:app --reload
```

Open http://127.0.0.1:8000/docs to test every endpoint.
The database file (app.db) is created automatically on first run.

## Endpoints

| Method | Path | Access |
|--------|------|--------|
| POST | /auth/register | Anyone |
| POST | /auth/token | Anyone (returns access_token and token_type) |
| GET | /users/me | Logged in |
| GET | /users/ | Admin only |
| PUT | /users/me | Logged in |
| DELETE | /users/me | Logged in |
| POST | /notes/ | Logged in |
| GET | /notes/ | Logged in (users: own + public notes, admins: all). Query params: tag, search_term |
| GET | /notes/{note_id} | Owner, admin, or public note |
| PUT | /notes/{note_id} | Owner or admin |
| DELETE | /notes/{note_id} | Owner or admin |

## Error handling

- 401: wrong username or password, invalid token, expired token
- 403: not enough permission (not admin, or not the note owner)
- 404: note not found
- 400: duplicate username or email, inactive user
