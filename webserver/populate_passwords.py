import random, string
import bcrypt
import psycopg2
from constants import DATABASEURI, MY_SALT

conn = psycopg2.connect(DATABASEURI)
cur = conn.cursor()

cur.execute("SELECT uid FROM users ORDER BY uid DESC")
results = cur.fetchall()

unencrypted_passwords = []
encrypted_passwords = []

for r in results:
    uid = r[0]
    N = random.randint(7, 18)
    unencrypted = ''.join(random.choices(string.ascii_letters + string.digits, k=N))
    unencrypted_passwords.append(unencrypted)
    encoded = unencrypted.encode('utf-8')
    hash = bcrypt.hashpw(encoded, MY_SALT)
    encrypted_passwords.append(hash)
    cur.execute("UPDATE users SET password=%s WHERE uid=%s", ((hash,), (uid,)))

conn.commit()


print(unencrypted_passwords)
