import sqlite3

conn = sqlite3.connect('db.db')
cursor = conn.cursor()

# Step 1: Create a new table with the DEFAULT value
cursor.execute("UPDATE auth SET isAdmin = 1 WHERE username = 'a';")

# cursor.execute("""
#     CREATE TABLE auth (
#         username TEXT,
#         password TEXT,
#         salt TEXT,
#         isAdmin INTEGER DEFAULT 0
#     );
# """)

# Commit and close
conn.commit()
conn.close()

