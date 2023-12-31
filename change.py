
from flask import Flask, render_template, request, url_for, session, redirect
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import datetime
import bcrypt
import re
import logging
import requests
from google_auth_oauthlib.flow import Flow
from authlib.integrations.flask_client import OAuth
import json

app = Flask(__name__)

appConf = {
    "OAUTH2_CLIENT_ID": "972501327114-sik46fo50ae64ld6stf6vdl3n2t6a3h0.apps.googleusercontent.com",
    "OAUTH2_CLIENT_SECRET": "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",
    "OAUTH2_META_URL": "https://accounts.google.com/.well-known/openid-configuration",
    "FLASK_SECRET": "2778368c-dd93-4d99-8f69-118fcc23b2a7",
    "FLASK_PORT": 5000      
}
app.secret_key = appConf.get("FLASK_SECRET")
oauth = OAuth(app)
oauth.register(
    name='google',
    client_id=appConf.get("OAUTH2_CLIENT_ID"),
    client_secret=appConf.get("OAUTH2_CLIENT_SECRET"),
    authorize_url='https://accounts.google.com/o/oauth2/auth',
    authorize_params=None,
    authorize_prompt_params=None,
    authorize_response=None,
    authorize_token_url='https://accounts.google.com/o/oauth2/token',
    authorize_token_params=None,
    client_kwargs={'scope': 'openid profile email https://www.googleapis.com/auth/user.birthday.read ', 
                   'redirect_uri': 'http://127.0.0.1:5000/auth'}
)



logging.basicConfig(filename='record.log', level=logging.DEBUG, format='%(asctime)s %(levelname)s %(name)s %(threadName)s : %(message)s')
dbname = 'User'
app.config['SQLALCHEMY_DATABASE_URI'] = f'postgresql://postgres:Hillgrange@localhost:5433/User'
# app.config['SQLALCHEMY_DATABASE_URL'] = 'postgres://username:password@localhost:5432/dbname'

db = SQLAlchemy(app)


class Loginn(db.Model):
    '''
    sno,username,password,timestamp
    '''
    sno = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(50), nullable=False)
    password = db.Column(db.String(200), nullable=False)
    timestamp = db.Column(db.DateTime, nullable=False)

class Salt(db.Model):
    email = db.Column(db.String(50), primary_key=True)
    salt = db.Column(db.String(200), nullable=False)

class Signup(db.Model):
    '''
    email,password,repeatpassword,timestamp
    '''
    email = db.Column(db.String(50), primary_key=True)
    password = db.Column(db.String(200), nullable=False)
    confirm_password = db.Column(db.String(200), nullable=False)
    timestamp = db.Column(db.DateTime, nullable=False)

class Bookic(db.Model):
    '''
    sno,name,email,phone,date_and_time,timestamp
    '''
    sno = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), nullable=False)
    email = db.Column(db.String(50), nullable=False)
    phone = db.Column(db.String(10), nullable=False)
    date_and_time = db.Column(db.DateTime, nullable=False)
    timestamp = db.Column(db.DateTime, nullable=False)

@app.route("/")
def homee():
    app.logger.info('Homepage accessed.')
    return render_template("index.html")

@app.route("/index2")
def home2():
    app.logger.info('Homepage 2 accessed.')
    return render_template("index2.html")

@app.route("/about")
def about():
    app.logger.info('About page accessed.')
    return render_template("about.html", session=session.get("user"), pretty=json.dumps(session.get("user"), indent = 4))

@app.route("/about1")
def about1():
    app.logger.info('About page 1 accessed.')
    return render_template("about1.html")

@app.route("/about2")
def about2():
    app.logger.info('About page 2 accessed.')
    return render_template("about2.html")

@app.route("/contact", methods=['GET', 'POST'])
def contact():
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        phone = request.form.get('phone')
        Subject = request.form.get('Subject')
        timestamp = datetime.datetime.now()

        if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
            app.logger.error('Invalid email address entered.')
            return "Invalid email address. Please try again."

        phone_regex = r'^\d{10,12}$'
        if not re.match(phone_regex, phone):
            error = "Phone number must be between 10 and 12 digits."
            app.logger.error('Invalid Phone Number entered.')
            return "Invalid Phone Number. Please try again."

        entry = Contacts(name=name, phone_num=phone, Subject=Subject, email=email, timestamp=timestamp)
        db.session.add(entry)
        db.session.commit()
        app.logger.info('Our team will reach out to you')
        return "Our team will reach out to you "

    app.logger.info("contact page accessed")
    return render_template("contact.html")

@app.route("/contact1", methods=['GET', 'POST'])
def contact1():
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        phone = request.form.get('phone')
        Subject = request.form.get('Subject')
        timestamp = datetime.datetime.now()

        if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
            app.logger.error('Invalid email address entered.')
            return "Invalid email address. Please try again."

        phone_regex = r'^\d{10,12}$'
        if not re.match(phone_regex, phone):
            error = "Phone number must be between 10 and 12 digits."
            app.logger.error('Invalid Phone Number entered.')
            return "Invalid Phone Number. Please try again."

        entry = Contacts(name=name, phone_num=phone, Subject=Subject, email=email, timestamp=timestamp)
        db.session.add(entry)
        db.session.commit()
        app.logger.info('Our team will reach out to you')
        return "Our team will reach out to you"

    app.logger.info("contact 1 page accessed")
    return render_template("contact1.html")

@app.route("/contact2", methods=['GET', 'POST'])
def contact2():
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        phone = request.form.get('phone')
        Subject = request.form.get('Subject')
        timestamp = datetime.datetime.now()

        if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
            app.logger.error('Invalid email address entered.')
            return "Invalid email address. Please try again."

        phone_regex = r'^\d{10,12}$'
        if not re.match(phone_regex, phone):
            error = "Phone number must be between 10 and 12 digits."
            app.logger.error('Invalid Phone Number entered.')
            return "Invalid Phone Number. Please try again."

        entry = Contacts(name=name, phone_num=phone, Subject=Subject, email=email, timestamp=timestamp)
        db.session.add(entry)
        db.session.commit()
        app.logger.info("Contact entry added successfully")
        return "Our team will reach out to you"

    app.logger.info("Our team will reach out to you")
    return render_template("contact2.html")

@app.route("/login_form", methods=['GET', 'POST'])
def logg():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get("password")
        timestamp = datetime.datetime.now()

        if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
            app.logger.error('Invalid email address entered.')
            return "Invalid email address. Please try again."

        user = Signup.query.filter_by(email=email).first()
        if not user:
            app.logger.warning('Invalid username or password entered.')
            return "Invalid username or password"

        hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        if bcrypt.checkpw(password.encode('utf-8'), user.password.encode('utf-8')):

            entry = Loginn(email=email, password=hashed, timestamp=timestamp)
            db.session.add(entry)
            db.session.commit()

            salt_entry = Salt.query.filter_by(email=email).first()
            if salt_entry:
                salt = salt_entry.salt
                hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt.encode('utf-8')).decode('utf-8')
                user = Signup.query.filter_by(email=email, password=hashed_password).first()
                if user:
                    app.logger.warning('User has successfully logged in.')
                    return render_template('index2.html', ans="Logged in successfully.")
                else:
                    app.logger.warning('Entry not found for the given user.')
                    return "Invalid username or password"

    app.logger.info("Login page accessed")
    return render_template('login_form.html')

@app.route("/sign_up", methods=['GET', 'POST'])
def sign_up():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get("password")
        confirm_password = request.form.get("confirm_password")
        timestamp = datetime.datetime.now()

        if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
            app.logger.error('Invalid email address entered.')
            return "Invalid email address. Please try again."

        if password != confirm_password:
            app.logger.error('Password and Confirm Password do not match. Please try again.')
            return "Password and Confirm Password do not match. Please try again."

        salt = bcrypt.gensalt().decode('utf-8')
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt.encode('utf-8')).decode('utf-8')

        user = Signup.query.filter_by(email=email).first()
        if user:
            app.logger.error('User already exists. Please log in.')
            return "User already exists. Please log in."

        entry = Signup(email=email, password=hashed_password, confirm_password=confirm_password, timestamp=timestamp)
        db.session.add(entry)
        db.session.commit()

        salt_entry = Salt(email=email, salt=salt)
        db.session.add(salt_entry)
        db.session.commit()

        app.logger.info('User signed up successfully.')
        return render_template('login_form.html', ans="User signed up successfully.")

    else:
        app.logger.debug('Returning sign-up page.')
        return render_template('sign_up.html')

@app.route("/bookc", methods=['GET', 'POST'])
def bookc():
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        phone = request.form.get('phone')
        date_and_time = request.form.get('date_and_time')
        timestamp = datetime.datetime.now()

        input_datetime = datetime.datetime.strptime(date_and_time, '%Y-%m-%dT%H:%M')
        current_datetime = datetime.datetime.now()
        if input_datetime <= current_datetime:
            app.logger.error('Invalid date and time entered.')
            return "Invalid date and time. Please try again."

        if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
            app.logger.error("Invalid email address entered.")
            return "Invalid email address. Please try again."

        phone_regex = r'^\d{10,12}$'
        if not re.match(phone_regex, phone):
            app.logger.error('Invalid Phone Number entered.')
            return "Invalid Phone Number. Please try again."

        existing_booking = Bookic.query.filter_by(date_and_time=date_and_time).first()
        if existing_booking:
            app.logger.error("The requested date and time slot is already booked.")
            return "The requested date and time slot is already booked. Please choose another slot."

        entry = Bookic(name=name, email=email, phone=phone, date_and_time=date_and_time, timestamp=timestamp)
        db.session.add(entry)
        db.session.commit()
        app.logger.info('Booking made successfully.')
        return "Booked successfully"

    app.logger.debug('Returning booking page.')
    return render_template("bookc.html")
@app.route('/login')
def login():
    redirect_uri = url_for('auth', _external=True)  # Make sure this points to your 'auth' route
    return oauth.google.authorize_redirect(redirect_uri)


@app.route('/auth')
def auth():
    token = oauth.google.authorize_access_token()
    user_info = oauth.google.parse_id_token(token)
    session['user'] = user_info
    return redirect(url_for('index'))

@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('index'))

@app.route('/')
def home():
    user = session.get('user')
    if user:
        return f"Hello, {user['name']}! <a href='/logout'>Logout</a>"
    else:
        return "You are not logged in. <a href='/login'>Login with Google</a>"


if __name__ == '__main__':
    app.run(debug=True)
