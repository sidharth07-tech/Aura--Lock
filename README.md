# Personal Notebook Web App

A simple Flask-based notebook application with:

- Phone number + password signup/login
- Phone verification via OTP
- Unique phone number per account
- One active session/device per account
- User-specific notes storage
- Unlimited note content length
- Notes saved with title, timestamp, and user data
- Search by title or date

## Setup

1. Create a virtual environment:
   ```bash
   python -m venv venv
   .\\venv\\Scripts\\activate
   ```
2. Install requirements:
   ```bash
   pip install -r requirements.txt
   ```
3. Run the app:
   ```bash
   python app.py
   ```
4. Open `http://127.0.0.1:5000`

## Notes

- OTP sending is simulated in the UI for demo purposes.
- This app uses SQLite for storage.
- Each user can only stay logged in on one device at a time.
