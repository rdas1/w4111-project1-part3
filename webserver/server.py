from flask import Flask, session, redirect, url_for, request, render_template, flash
from markupsafe import escape
from constants import SECRET_KEY, DATABASEURI
import psycopg2
import geocoder

def get_db_connection():
    conn = psycopg2.connect(DATABASEURI)
    return conn, conn.cursor()

def get_user_name(uid):
    conn, cur = get_db_connection()
    cur.execute("SELECT * FROM individuals WHERE uid=%s", (uid,))
    result = cur.fetchone()
    if result is not None:
        cur.close()
        conn.close()
        return f"{result[1]} {result[2]}"
    cur.execute("SELECT * FROM organizations WHERE uid=%s", (uid,))
    result = cur.fetchone()
    cur.close()
    conn.close()
    if result is not None:
        return f"{result[1]}"
    return -1

def get_map_markers():
    conn, cur = get_db_connection()
    cur.execute("SELECT * FROM user_create_events WHERE event_date >= current_date")
    # TODO: implement date range
    # TODO: implement filtering by interest/ca
    events = cur.fetchall()
    markers = []
    for e in events:
        organizer_uid = e[0]
        organizer_name = get_user_name(organizer_uid)
        organizer_link = f"/user/{organizer_uid}"
        address = ', '.join([e[5], 'New York, NY', str(e[10])])
        title = e[2]
        description = e[3]
        date = str(e[13])
        popup = f"""<h1><strong>{title}</strong></h1><h2>Posted by {organizer_name}</h2>{description}"""
        #popup = f"""<h1><strong>{title}</strong></h1><h2><i>Posted by {organizer_link}</i></h2>{description}"""
        print(popup)
        [lat, lng] = geocoder.arcgis(address).latlng
        markers.append({'lat': lat, 'lon': lng, 'title': title, 'date': date, 'organizer_name': organizer_name, 'organizer_link': organizer_link, 'description': description, 'popup': popup})
    cur.close()
    conn.close()
    return markers

app = Flask(__name__)

# Set the secret key to some random bytes. Keep this really secret!
# I'll update this later to store secret key in hidden file
app.secret_key = SECRET_KEY

@app.route('/')
def index():
    if 'uid' in session:
        return redirect(url_for('map_view'))
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
    session.pop('uid', None)
    return redirect(url_for('index'))

@app.route('/map')
def map_view():
    if 'uid' not in session:
        return redirect(url_for('login'))
    markers = get_map_markers()
    return render_template('map_view.html', markers=markers)

@app.route('/list')
def list_view():
    if 'uid' not in session:
        return redirect(url_for('login'))
    return render_template('list_view.html')

@app.route('/event/<eid>')
def event_page(eid):
    conn, cur = get_db_connection()
    cur.execute("SELECT * FROM user_create_events WHERE eid=%s", (eid,))
    e = cur.fetchone()
    if e is None:
        return render_template('event.html', not_found=True)
    organizer_uid = e[0]
    date = str(e[13])
    print(date)
    organizer_name = get_user_name(organizer_uid)
    organizer_link = f"/user/{organizer_uid}"
    address = ', '.join([e[5], 'New York, NY', str(e[10])])
    # TODO: format address with building numbers (if not null)
    title = e[2]
    description = e[3]
    #[lat, lng] = geocoder.arcgis(address).latlng
    info = {'address': address, 'date': date, 'title': title, 'organizer_name': organizer_name, 'organizer_link': organizer_link, 'description': description}
    # TODO: add comments to event page
    return render_template('event.html', info=info)

@app.route('/user/<uid>')
def user_page(uid):
    conn, cur = get_db_connection()
    cur.execute("SELECT * FROM user_create_events WHERE uid=%s", (uid,))
    events = cur.fetchall()
    name = get_user_name(uid)
    cur.close()
    conn.close()
    return render_template('user_page.html', name=name, events=events)

@app.route('/event/create')
def create_event():
    return render_template("create_event.html")

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=4000)

