import sqlite3
import bcrypt
import logging

logging.basicConfig(filename='app.log', level=logging.INFO)

def add_user(username, password):
    try:
        conn = sqlite3.connect('users.db')
        c = conn.cursor()

        # Hash the password using bcrypt
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        # Use a parameterized query to prevent SQL injection
        c.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, hashed_password))
        conn.commit()

        logging.info(f"User '{username}' added successfully.")
    except Exception as e:
        logging.error(f"Error adding user: {e}")
        raise

# Example usage
add_user("Alex", "123")
