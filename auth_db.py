import sqlite3
import threading
import time

class AuthDB:
    def __init__(self, db_name='auth_users.db',default_session_time=3600):
        self.db_name = db_name
	self.default_session_time = default_session_time
        self.lock = threading.Lock()
        self._create_table()

    def _create_table(self):
        with self.lock, sqlite3.connect(self.db_name) as conn:
            cursor = conn.cursor()
            cursor.execute(
                '''CREATE TABLE IF NOT EXISTS active_users (
		    username TEXT PRIMARY KEY,
                    ip TEXT NOT NULL,
                    expiry_time INTEGER NOT NULL
                )'''
            )
            conn.commit()

    def add_user(self, username, ip):
	session_time=self.default_session_time
        expiry_time = int(time.time()) + session_time
	if ip is None:
            with self.lock, sqlite3.connect(self.db_name) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    '''INSERT OR REPLACE INTO active_users (username, ip, expiry_time)
                    VALUES (?, ?, ?) '''
                  , (username, NONE, expiry_time))
	else:
	     with self.lock, sqlite3.connect(self.db_name) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    '''INSERT OR REPLACE INTO active_users (username, ip, expiry_time)
                    VALUES (?, ?, ?)
                ''', (username, ip, expiry_time))

        conn.commit()

    def remove_user(self, username):
        with self.lock, sqlite3.connect(self.db_name) as conn:
            cursor = conn.cursor()
            cursor.execute('DELETE FROM active_users WHERE username = ?', (username,))
            conn.commit()

    def is_authenticated(self, username):
        current_time = int(time.time())
        with self.lock, sqlite3.connect(self.db_name) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT expiry_time FROM active_users WHERE username = ?', (username,))
            result = cursor.fetchone()
            if result and result[0] > current_time:
                return True
            return False

    def cleanup_expired_users(self):
        current_time = int(time.time())
        with self.lock, sqlite3.connect(self.db_name) as conn:
            cursor = conn.cursor()
            cursor.execute('DELETE FROM active_users WHERE expiry_time <= ?', (current_time,))
            conn.commit()

def cleanup_task(auth_db, interval=60):
    while True:
        auth_db.cleanup_expired_users()
        time.sleep(interval)
