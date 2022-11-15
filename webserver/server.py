from flask import Flask, session, redirect, url_for, request, render_template, flash
from markupsafe import escape
from constants import SECRET_KEY, DATABASEURI, ZIPCODES, MY_SALT
import psycopg2
import geocoder
import bcrypt

def get_db_connection():
    conn = psycopg2.connect(DATABASEURI)
    conn.autocommit = True
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
        eid = e[1]
        event_link = f"/event/{eid}"
        organizer_uid = e[0]
        organizer_name = get_user_name(organizer_uid)
        organizer_link = f"/user/{organizer_uid}"
        address = ', '.join([e[5], 'New York, NY', str(e[10])])
        title = e[2]
        description = e[3]
        date = str(e[13])
        [lat, lng] = geocoder.arcgis(address).latlng
        markers.append({'lat': lat, 'lon': lng, 'event_link': event_link, 'title': title, 'date': date, 'organizer_name': organizer_name, 'organizer_link': organizer_link, 'description': description})
    cur.close()
    conn.close()
    return markers

app = Flask(__name__)

# Set the secret key to some random bytes. Keep this really secret!
# I'll update this later to store secret key in hidden file
app.secret_key = SECRET_KEY

@app.route('/')
def index():
    return render_template("index.html")


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        encoded = request.form["password"].encode("utf-8")
        encrypted = bcrypt.hashpw(encoded, MY_SALT)
        conn, cur = get_db_connection()
        cur.execute("select uid from users where email=%s", (email,))
        result = cur.fetchone()
        if result is None:
            cur.close()
            conn.close()
            return render_template('login.html', error=True)
        uid = result[0]
        cur.execute("SELECT uid FROM users WHERE password=%s", (encrypted,))
        result = cur.fetchone()
        if result is None:
            return render_template('login.html', error=True)
        session['uid'] = uid
        session['email'] = email
        session['name'] = get_user_name(uid)
        return redirect(url_for('map'))
    return render_template('login.html')

@app.route('/logout')
def logout():
    # remove the username from the session if it's there
    session.pop('email', None)
    session.pop('uid', None)
    return redirect(url_for('login'))

@app.route('/signup', methods=['GET', 'POST'])
def signup_step1():
    if request.method == 'POST':
        if "zip" not in request.form:
            return render_template('signup.html', invalid_zip=True)
        if not request.form["zip"].isnumeric():
            return render_template('signup.html', invalid_zip=True)
        if "user_type" not in request.form:
            return render_template('signup.html', invalid_user_type=True)

        #TODO: check if DOB at least 13 ago

        conn, cur = get_db_connection()
        cur.execute("select uid from users where email=%s", (request.form['email'].lower(),))
        result = cur.fetchone()
        if result is not None: # i.e. an account has already been registered with this email address
            cur.close()
            conn.close()
            return render_template('signup.html', already_exists=True)
        
        # Hash password:
        encoded = request.form["password"].encode("utf-8")
        encrypted = bcrypt.hashpw(encoded, MY_SALT)
        
        cur.execute("SELECT MAX(uid) FROM users")
        #print("hello from line 108")
        last_uid = cur.fetchone()[0]
        new_uid = last_uid + 1
        #TODO: insert hashed password into DB
        data_to_insert = (new_uid, request.form['email'].lower(), request.form['dob'], int(request.form['zip']))
        #print(data_to_insert)
        cur.execute("INSERT INTO users VALUES (%s, %s, %s, %s, %s)", ((new_uid,), (request.form["email"].lower(),), (request.form["dob"],), (int(request.form['zip']),), (encrypted,)))
        conn.commit()
        session['email'] = request.form['email'].lower()
        session['uid'] = new_uid
        cur.close()
        conn.close()
        if request.form['user_type'] == 'organization':
            return redirect(url_for('signup_organization', uid=new_uid))
        return redirect(url_for('signup_individual', uid=new_uid))
    return render_template('signup.html')

@app.route('/signup/individual/<uid>', methods=['GET', 'POST'])
def signup_individual(uid):
    if request.method == "POST":
        # TODO: validate form data and insert into Individuals
        conn, cur = get_db_connection()
        cur.execute("SELECT * FROM users WHERE uid=%s", (uid,))
        if cur.fetchone() is None:
            cur.close()
            conn.close()
            return render_template("signup_individual.html", uid_not_found=True)
        cur.execute("SELECT * FROM individuals WHERE uid=%s", (uid,))
        if cur.fetchone() is not None:
            return render_template("signup_individual.html", individual_already_exists=True)
        first_name = request.form["firstname"]
        last_name = request.form["lastname"]
        interests = [int(i) for i in request.form.getlist("interests")]
        conn, cur = get_db_connection()
        cur.execute("INSERT INTO individuals VALUES (%s, %s, %s)", ((uid,),(first_name,), (last_name,)))
        #interests_to_insert = tuple([(uid, i) for i in interests])
        for i in interests:
            cur.execute("INSERT INTO individual_interested_in_category VALUES (%s, %s)", ((uid,), (i,)))
        conn.commit()
        return redirect(url_for("map_view"))

    return render_template("signup_individual.html")

#TODO: signup for organizations
# should uid be in URL?
@app.route('/signup/organization/<uid>', methods=['GET', 'POST'])
def signup_organization(uid):
    if request.method == "POST":
        # TODO: validate form data and insert into Organizations
        print("hello")
    return render_template("signup_individual.html")

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
    app.run(host='0.0.0.0', port=8111)

