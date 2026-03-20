# Password Strength Check

This project validates the admin password before saving a password change.

## Summary

A new admin password is accepted only when it includes all of the following:

- at least 8 characters
- at least one uppercase letter
- at least one lowercase letter
- at least one number
- at least one symbol

Example of a valid password:

```text
StrongPass1!
```

## Where It Runs

The validation currently exists in two places:

1. Frontend pre-check in `web/scripts/settings.js`
2. Backend enforcement in `src/auth.py`

The frontend gives immediate feedback in the Settings screen, while the backend is the final source of truth before the password hash is written to `auth.json`.

## Backend Rules

The backend validator is implemented in `_validate_password_strength(...)` in `src/auth.py`.

Current checks:

- `len(password) < 8` rejects passwords shorter than 8 characters
- `r"[A-Z]"` requires an uppercase letter
- `r"[a-z]"` requires a lowercase letter
- `r"\d"` requires a digit
- `r"[^A-Za-z0-9]"` requires a non-alphanumeric character

If a rule fails, the backend raises `ValueError` with a specific message such as:

- `Password must be at least 8 characters long`
- `Password must include at least one uppercase letter`
- `Password must include at least one lowercase letter`
- `Password must include at least one number`
- `Password must include at least one symbol`

## Frontend Behavior

The Settings page uses this regex before calling the backend:

```text
/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^A-Za-z0-9]).{8,}$/
```

If the password does not match, the UI shows:

```text
Use 8+ chars with uppercase, lowercase, number, and symbol
```

The frontend also checks that:

- both password fields are filled in
- `newPassword` and `confirmPassword` match

## Password Update Flow

1. The user enters a new password and confirmation in the Settings page.
2. The frontend validates format and matching values.
3. The frontend calls `eel.update_admin_password(newP)()`.
4. The backend calls `change_password(new_password)`.
5. `change_password(...)` runs `_validate_password_strength(...)`.
6. If valid, the password is hashed with `bcrypt` and saved to `auth.json`.

## Important Note

The default bootstrap password is currently `usbguard123`, defined in `src/auth.py`.

That default password does not satisfy the strength rules above because it has no uppercase letter and no symbol. The stronger validation is applied when the password is changed, not when the default credentials are first created.
