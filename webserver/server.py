from flask import Flask, session, redirect, url_for, request, render_template, flash
from markupsafe import escape
from constants import SECRET_KEY, DATABASEURI
import psycopg2
import geocoder

def get_db_connection():
    conn = psycopg2.connect(DATABASEURI)
    return conn, conn.cursor()

def get_map_markers():
    conn, cur = get_db_connection()
    cur.execute("SELECT * FROM user_create_events WHERE event_date >= current_date")
    # TODO: implement date range
    # TODO: implement filtering by interest/ca
    events = cur.fetchall()
    markers = []
    for e in events:
        address = ', '.join([e[5], 'New York, NY', str(e[10])])
        title = e[2]
        description = e[3]
        popup = f"""<strong>{e[2]}</strong>{e[3]}"""
        print(popup)
        [lat, lng] = geocoder.arcgis(address).latlng
        markers.append({'lat': lat, 'lon': lng, 'title': title, 'description': description, 'popup': popup})
    cur.close()
    conn.close()
    return markers

app = Flask(__name__)

# Set the secret key to some random bytes. Keep this really secret!
# I'll update this later to store secret key in hidden file
app.secret_key = SECRET_KEY

@app.route('/')
def index():
    if 'email' in session:
        return redirect(url_for('map_view'))
        #return render_template('index.html', logged_in=True, email=session['email'])
    else:
        return render_template('index.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        conn, cur = get_db_connection()
        data = (request.form['email'],)
        cur.execute("select uid from users where email=%s", data)
        row = cur.fetchone()
        cur.close()
        conn.close()
        if row is not None:
            print(row)
            session['uid'] = row[0]
            session['email'] = data[0]
            return redirect(url_for('index'))
        else:
            return render_template('login.html', error=True)
    return render_template('login.html')

@app.route('/logout')
def logout():
    # remove the username from the session if it's there
    session.pop('email', None)
    return redirect(url_for('index'))

@app.route('/map')
def map_view():
    if 'email' not in session:
        return redirect(url_for('login'))
    markers = get_map_markers()
    return render_template('map_view.html', email=(session['email'],), markers=markers)

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=4000)