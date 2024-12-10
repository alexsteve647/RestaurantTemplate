import sqlite3

def init_db():
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (username TEXT PRIMARY KEY, password TEXT, first_name TEXT, last_name TEXT, email TEXT, photo_url TEXT)''')
    conn.commit()
    conn.close()

def get_user(username, password=None):
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    if password:
        c.execute('SELECT * FROM users WHERE username=? AND password=?', (username, password))
    else:
        c.execute('SELECT * FROM users WHERE username=?', (username,))
    user = c.fetchone()
    conn.close()
    if user:
        return {'username': user[0], 'password': user[1], 'first_name': user[2], 'last_name': user[3], 'email': user[4], 'photo_url': user[5]}
    return None

def add_user(username, password, first_name, last_name, email, photo_url):
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('INSERT INTO users (username, password, first_name, last_name, email, photo_url) VALUES (?, ?, ?, ?, ?, ?)',
              (username, password, first_name, last_name, email, photo_url))
    conn.commit()
    conn.close()
