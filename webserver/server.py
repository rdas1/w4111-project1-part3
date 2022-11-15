from flask import Flask, session, redirect, url_for, request, render_template, escape
from markupsafe import escape
from constants import SECRET_KEY, DATABASEURI, ZIPCODES
import psycopg2
import geocoder
import bcrypt
from datetime import timezone
import datetime
import time

def get_db_connection():
    conn = psycopg2.connect(DATABASEURI)
    conn.autocommit = True
    return conn, conn.cursor()

def is_individual(uid):
    conn, cur = get_db_connection()
    cur.execute("SELECT * FROM individuals WHERE uid=%s", (uid,))
    result = cur.fetchone()
    if result is not None:
        cur.close()
        conn.close()
        return True
    return False

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
    return "unknown name"

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
        address_components = []
        if e[6] is not None and e[5] is not None:
            address_components.append(f"{e[6]} {e[5]}")
        elif e[5] is not None:
            address_components.append(e[5])
        address_components.append('New York, NY')
        address_components.append(str(e[10]))
        address = ', '.join(address_components)
        title = e[2]
        #description = escape(e[3])
        #description = 'Lorem ipsum doloret'
        date = str(e[13])
        status = e[9]
        [lat, lng] = geocoder.arcgis(address).latlng
        markers.append({'lat': lat, 'lon': lng, 'event_link': event_link, 'title': title, 'date': date, 'organizer_name': organizer_name, 'organizer_link': organizer_link, 'status': status})
        print({'lat': lat, 'lon': lng, 'event_link': event_link, 'title': title, 'date': date, 'organizer_name': organizer_name, 'organizer_link': organizer_link, 'status': status})
        print('---')
    #print(markers)
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
        session["name"]  = get_user_name(session["uid"])
    return render_template("index.html")


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form["password"].encode("utf-8")
        #encoded = request.form["password"].encode("utf-8")
        #hashed = bcrypt.hashpw(encoded, MY_SALT)
        conn, cur = get_db_connection()
        cur.execute("select uid, password from users where email=%s", (email,))
        result = cur.fetchone()
        if result is None:
            cur.close()
            conn.close()
            return render_template('login.html', error=True)
        uid = result[0]
        hashed_password = result[1].encode('utf-8')
        print("hashed_password: ", hashed_password)
        if bcrypt.hashpw(password, hashed_password) == hashed_password:
            session['uid'] = uid
            session['email'] = email
            session['name'] = get_user_name(uid)
            
            return redirect(url_for('map_view'))
        return render_template('login.html', error=True)
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
        hashed = bcrypt.hashpw(encoded, MY_SALT).decode()
        
        cur.execute("SELECT MAX(uid) FROM users")
        #print("hello from line 108")
        last_uid = cur.fetchone()[0]
        new_uid = last_uid + 1
        #TODO: insert hashed password into DB
        data_to_insert = (new_uid, request.form['email'].lower(), request.form['dob'], int(request.form['zip']))
        #print(data_to_insert)
        cur.execute("""INSERT INTO users VALUES (%s, %s, %s, %s, %s)""", ((new_uid,), (request.form["email"].lower(),), (request.form["dob"],), (int(request.form['zip']),), (hashed,)))
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
        if "org_name" not in request.form:
            return render_template("signup_organization.html", invalid_org_name=True)
        if "building_number" not in request.form or "street_addr" not in request.form:
            return render_template("signup_organization.html", invalid_address=True)
        if "org_type" not in request.form:
            return render_template("signup_organization.html", invalid_org_type=True)
        conn, cur = get_db_connection()
        cur.execute("SELECT * FROM users WHERE uid=%s", (uid,))
        if cur.fetchone() is None:
            cur.close()
            conn.close()
            return render_template("signup_organization.html", uid_not_found=True)
        cur.execute("SELECT * FROM organizations WHERE uid=%s", (uid,))
        if cur.fetchone() is not None:
            return render_template("signup_organization.html", organization_already_exists=True)
        org_name = request.form["org_name"]
        building_number = request.form["building_number"]
        street_addr = request.form["street_addr"]
        building_unit = None
        if "building_unit" in request.form:
            building_unit = request.form["building_unit"]
        link = None
        if "link" in request.form:
            link = request.form["link"]
        org_type = request.form["org_type"]
        cur.execute("INSERT INTO organizations VALUES (%s,%s,%s,%s,%s,%s,%s)", ((uid,), (org_name,), (street_addr,), (building_number,), (building_unit,), (link,), (org_type,)))
        conn.commit()
        cur.close()
        conn.close()
        return redirect(url_for('map_view'))
    return render_template("signup_organization.html")

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
    conn, cur = get_db_connection()
    cur.execute("SELECT * FROM user_create_events WHERE event_date >= current_date ORDER BY event_date ASC")
    events = cur.fetchall()
    cards = []
    for e in events:
        eid = e[1]
        event_link = url_for("event_page", eid=eid)
        organizer_uid = e[0]
        organizer_name = get_user_name(organizer_uid)
        organizer_link = url_for("user_page", uid=organizer_uid)
        address_components = []
        if e[6] is not None and e[5] is not None:
            address_components.append(f"{e[6]} {e[5]}")
        elif e[5] is not None:
            address_components.append(e[5])
        address_components.append('New York, NY')
        address_components.append(str(e[10]))
        address = ', '.join(address_components)
        title = e[2]
        description = e[3]
        #description = 'Lorem ipsum doloret'
        date = str(e[13])
        status = e[9]
        [lat, lng] = geocoder.arcgis(address).latlng
        cards.append({'lat': lat, 'lon': lng, 'event_link': event_link, 'title': title, 'date': date, 'organizer_name': organizer_name, 'organizer_link': organizer_link, 'status': status})
    
    return render_template('list_view.html', cards=cards)

@app.route('/event/<eid>', methods=['GET', 'POST'])
def event_page(eid):
    conn, cur = get_db_connection()
    if request.method == "POST":
        if "comment_body" in request.form and "uid" in session:
            cur.execute("SELECT MAX(cid) FROM user_post_comment")
            last_cid = cur.fetchone()[0]
            new_cid = last_cid + 1
            #dt = datetime.datetime.now(timezone.utc)
            #utc_time = dt.replace(tzinfo=timezone.utc)
            utc_timestamp = datetime.datetime.now()
            cur.execute("INSERT INTO user_post_comment VALUES (%s, %s, %s, %s, %s)", ((new_cid,), (utc_timestamp,), (request.form["comment_body"],), (session["uid"],), (eid,)))
            conn.commit()
            #cur.close()
            #conn.close()
            #return render_template("event.html")
    cur.execute("SELECT * FROM user_create_events WHERE eid=%s", (eid,))
    e = cur.fetchone()
    if e is None:
        cur.close()
        conn.close()
        return render_template('event.html', not_found=True)
    eid = e[1]
    event_link = f"/event/{eid}"
    organizer_uid = e[0]
    organizer_name = get_user_name(organizer_uid)
    organizer_link = f"/user/{organizer_uid}"
    address_components = []
    if e[6] is not None and e[5] is not None:
        address_components.append(f"{e[6]} {e[5]}")
    elif e[5] is not None:
        address_components.append(e[5])
    address_components.append('New York, NY')
    address_components.append(str(e[10]))
    address = ', '.join(address_components)
    title = e[2]
    #description = escape(e[3])
    #description = 'Lorem ipsum doloret'
    date = str(e[13])
    status = e[9]
    description = e[3]
    status = e[9]
    cur.execute("SELECT catid FROM event_has_category WHERE eid=%s", (eid,))
    result = cur.fetchone()
    categories = ["Unknown", "Sports", "Politics", "Culture", "Film", "Arts", "Volunteer"]
    if result is  None:
        c = 0
    else:
        c = result[0]
    category = categories[c]
    #[lat, lng] = geocoder.arcgis(address).latlng

    cur.execute("SELECT * FROM user_post_comment WHERE eid=(%s)", (eid,))
    comments_unformatted = cur.fetchall()
    comments = []
    for c in comments_unformatted:
        comm = {}
        comm["poster_uid"] = c[3]
        comm["poster_name"] = get_user_name(c[3])
        comm["timestamp"] = c[1]
        comm["body"] = c[2]
        cur.execute("SELECT cid_original FROM comment_replies_to_comment WHERE cid_reply=%s", (c[0],))
        result = cur.fetchone()
        if result is None:
            comm["replying_to"] = -1
        else:
            comm["replying_to"] = result[0]
        comments.append(comm)


    info = {'eid': eid, 'address': address, 'date': date, 'title': title, 'organizer_name': organizer_name, 'organizer_link': organizer_link, 'description': description, 'status': status, 'category': category, 'num_comments': len(comments)}
    # TODO: add comments to event page
    return render_template('event.html', info=info, comments=comments)

@app.route('/user/<uid>')
def user_page(uid):
    if uid == session['uid']:
        return redirect(url_for("my_account"))
    conn, cur = get_db_connection()
    cur.execute("SELECT * FROM user_create_events WHERE uid=%s", (uid,))
    events = cur.fetchall()
    name = get_user_name(uid)
    cur.close()
    conn.close()
    return render_template('user_page.html', uid=uid, name=name, events=events)

@app.route('/event/create', methods=['GET', 'POST'])
def create_event():
    if "uid" not in session:
        return redirect(url_for("login"))
    uid = session["uid"]
    if request.method == "POST":
        title = request.form["title"]
        description = request.form["description"]
        street_addr = request.form["street_addr"]
        building_number = request.form["building_number"]
        if "building_unit" in request.form:
            building_unit = request.form["building_unit"]
        event_date = request.form["event_date"]
        if request.form["repeat_frequency"] == "no":
            is_repeating = False
            repeat_frequency = None
        else:
            is_repeating = True
            repeat_frequency = request.form["repeat_frequency"]
        link = None
        if "link" in request.form:
            link = request.form["link"]
        start_time = None
        end_time = None
        if "start_time" in request.form:
            start_time = f'{event_date} {request.form["start_time"]}'
            print(start_time)
            print(type(start_time))
        if "end_time" in request.form:
            end_time = f'{event_date} {request.form["end_time"]}'
            print(end_time)
            print(type(end_time))
        category = request.form["category"]
        print("hello 1")
        event_status = request.form["event_status"]
        print("hello 1.5")
        zipcode = request.form["zipcode"]
        print("hello 2")
        conn, cur = get_db_connection()
        cur.execute("SELECT MAX(eid) FROM user_create_events")
        last_eid = cur.fetchone()[0]
        new_eid = last_eid + 1
        print("hello 3")
        repeat_frequency = None
        repeat_until = None

        data_to_insert = ((uid,), (new_eid,), (title,), (description,), (is_repeating,), (street_addr,), (building_number,), (building_unit,), (link,), (event_status,), (zipcode,), None, None, (event_date,), (start_time,), (end_time,))
        print(len(data_to_insert)) 
        cur.execute("INSERT INTO user_create_events VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)", ((uid,), (new_eid,), (title,), (description,), (is_repeating,), (street_addr,), (building_number,), (building_unit,), (link,), (event_status,), (zipcode,), (repeat_frequency,), (repeat_until,), (event_date,), (start_time,), (end_time,)))
        cur.execute("INSERT INTO event_has_category VALUES (%s, %s)", (uid,), (category,))
        conn.commit()
        cur.close()
        conn.close()
        return redirect(url_for("map_view"))
    return render_template("create_event.html")

@app.route('/rsvp/<eid>', methods=['GET'])
def rsvp(eid):
    if 'uid' not in session:
        return redirect(url_for('login'))
    uid = session['uid']
    if not is_individual(uid):
        return redirect(url_for('index'))
    conn, cur = get_db_connection()
    cur.execute("INSERT INTO individual_rsvp_event VALUES (%s, %s, %s)", ((uid,), (eid,), (False,)))
    cur.close()
    conn.close()
    return redirect(url_for('my_account'))

@app.route('/myaccount', methods=['GET'])
def my_account():
    if 'uid' not in session:
        return redirect(url_for('login')) 
    uid = session.get('uid')
    conn, cur = get_db_connection()
    cur.execute("SELECT r.eid, e.title FROM individual_rsvp_event as r, user_create_events as e WHERE r.uid = (%s) AND r.eid=e.eid", (uid,))
    RSVPs = cur.fetchall()
    cur.execute("SELECT e.eid, e.title FROM user_create_events as e WHERE (e.uid=%s)", (uid,))
    organized = cur.fetchall()
    cur.close()
    conn.close()
    return render_template("my_account.html", RSVPs=RSVPs, organized=organized)

@app.route('/message/', methods=['GET'])
def show_messages():
    uid = session["uid"]
    conn, cur = get_db_connection()
    cur.execute("SELECT DISTINCT r.uid FROM user_send_message as s, user_receive_message as r WHERE s.mid=r.mid AND s.uid=%s", (uid,))
    receiver_uids = cur.fetchall()
    cur.execute("SELECT DISTINCT s.uid FROM user_send_message as s, user_receive_message as r WHERE s.mid=r.mid AND r.uid=%s", (uid,))
    sender_uids = cur.fetchall()
    messager_uids = receiver_uids + sender_uids
    messagers = [(m_uid, get_user_name(m_uid)) for m_uid in messager_uids]
    cur.close()
    conn.close()
    if len(messagers) > 0:
        return render_template("conversations.html", messagers=messagers)
    return render_template("conversations.html", no_messages=True)

@app.route('/message/<receiver>', methods=['GET', 'POST'])
def send_message(receiver):
    uid = session["uid"]
    conn, cur = get_db_connection()
    if request.method == "POST":
        cur.execute("SELECT MAX(mid) FROM user_send_message")
        last_mid = cur.fetchone()[0]
        new_mid = last_mid + 1
        data1 = ((uid,), (new_mid,), (request.form["new_m_body"],))
        cur.execute("INSERT INTO user_send_message VALUES (%s, %s, %s)", data1)
        conn.commit()
        cur.execute("INSERT INTO user_receive_message VALUES (%s, %s)", ((receiver,), (new_mid,)))
        conn.commit()
        return redirect(url_for('send_message', receiver=receiver))

    cur.execute("SELECT user_send_message.mid, user_send_message.m_body, user_send_message.uid, user_receive_message.uid FROM user_send_message, user_receive_message WHERE (user_send_message.uid=%s AND user_receive_message.uid=%s) OR (user_send_message.uid=%s AND user_receive_message.uid=%s) ORDER BY user_send_message.mid ASC", ((uid,), (receiver,), (receiver,), (uid,)) )
    messages = cur.fetchall()
    messages = [(m[0], m[1], get_user_name(m[2]), get_user_name(m[3])) for m in messages]
    return render_template("messaging.html", messages=messages)
    

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=8111)

