from flask import Flask, render_template, request, session, url_for, redirect
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from flask_migrate import Migrate
import datetime
import bcrypt
import re
import logging
import json
import secrets
import rauth
import requests
from rauth import OAuth2Service
from rauth.service import OAuth2Service

app = Flask(__name__)

app.config['GITHUB_CLIENT_ID'] = 'ab5f7b0fd7e0c21f9cc8'
app.config['GITHUB_CLIENT_SECRET'] = 'cb4e3a5d36af588936c1aec759354dd11b0dcd79'
REDIRECT_URI = 'http://127.0.0.1:5000/github_callback'


github_oauth = OAuth2Service(
    client_id='ab5f7b0fd7e0c21f9cc8',
    client_secret='cb4e3a5d36af588936c1aec759354dd11b0dcd79',
    name='github',
    authorize_url='https://github.com/login/oauth/authorize',
    access_token_url='https://github.com/login/oauth/access_token',
    base_url='https://api.github.com/',
)

app.secret_key = secrets.token_hex(16)



logging.basicConfig(filename='record.log', level=logging.DEBUG, format='%(asctime)s %(levelname)s %(name)s %(threadName)s : %(message)s')
dbname = 'User'
app.config['SQLALCHEMY_DATABASE_URI'] = f'postgresql://postgres:Hillgrange@localhost:5433/User2'
# app.config['SQLALCHEMY_DATABASE_URL'] = 'postgres://username:password@localhost:5432/dbname'

db = SQLAlchemy(app)
migrate = Migrate(app, db)

class Loginn(db.Model):
    '''
    sno,username,password,timestamp
    '''
    sno = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(200), nullable=False)
    github_username = db.Column(db.String(100))
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
    doctor=db.Column(db.String(80), nullable=False)
    timestamp = db.Column(db.DateTime, nullable=False)


@app.route("/index2")
def home2():
    app.logger.info('Homepage 2 accessed.')

    # Get the GitHub user data from the session
    github_user_data = session.get('github_user_data')

    # Check if the user data is available
    if github_user_data:
        # Pass the user data to the template
        return render_template("index2.html", github_user_data=github_user_data)
    else:
        return "User not authenticated."


@app.route("/about")
def about():
    app.logger.info('About page accessed.')
    return render_template("about.html", session=session.get("user"), pretty=json.dumps(session.get("user"), indent = 4))


@app.route("/about2")
def about2():
    app.logger.info('About page 2 accessed.')
    return render_template("about2.html")

@app.route("/contact", methods=['GET', 'POST'])
def contact():
    app.logger.info("contact page accessed")
    return render_template("contact.html")

@app.route('/login_form', methods=['GET', 'POST'])
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
            # Check if the user has a GitHub login associated with their email
            github_login = Loginn.query.filter_by(email=email).first()
            
            if github_login:
                # The user has logged in with GitHub
                app.logger.warning('User has successfully logged in with GitHub.')
                return render_template('index2.html', ans="Logged in successfully.")
            else:
                # The user has logged in traditionally
                entry = Loginn(email=email, password=hashed, github_username='', timestamp=timestamp)
                db.session.add(entry)
                db.session.commit()
                app.logger.warning('User has successfully logged in with traditional login.')
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
        doctor=request.form.get('doctor')
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

        entry = Bookic(name=name, email=email, phone=phone, date_and_time=date_and_time, doctor=doctor, timestamp=timestamp)
        db.session.add(entry)
        db.session.commit()
        app.logger.info('Booking made successfully.')
        return "Booked successfully"

    app.logger.debug('Returning booking page.')
    return render_template("bookc.html")

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/github_login')
def login():
    redirect_uri = url_for('github_callback', _external=True)
    params = {
        'redirect_uri': redirect_uri,
        'scope': 'user',  # Customize the scope as needed
    }
    auth_url = github_oauth.get_authorize_url(**params)
    return redirect(auth_url)

@app.route('/github_callback')
def github_callback():
    code = request.args.get('code')
    if code:
        # Use the code to obtain an access token from GitHub
        data = {
            'code': code,
            'redirect_uri': REDIRECT_URI,
            'client_id': 'ab5f7b0fd7e0c21f9cc8',
            'client_secret': 'cb4e3a5d36af588936c1aec759354dd11b0dcd79',
        }
        response = requests.post(github_oauth.access_token_url, data=data, headers={'Accept': 'application/json'})
        
        if response.status_code == 200:
            access_token = response.json()['access_token']

            # Use the access token to fetch user data from GitHub
            user_data_response = requests.get('https://api.github.com/user', headers={'Authorization': f'Bearer {access_token}'})
            
            if user_data_response.status_code == 200:
                user_data = user_data_response.json()

                # Store user data in the session (customize as needed)
                session['github_user_data'] = user_data

                # Store GitHub login credentials in the Loginn table
                email = user_data['email']  # You should handle the case where 'email' is None
                password = secrets.token_hex(16)  # Generate a random password for GitHub logins
                github_username = user_data['login']
                timestamp = datetime.datetime.now()

                hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
                entry = Loginn(email=email, password=hashed_password, github_username=github_username, timestamp=timestamp)
                db.session.add(entry)
                db.session.commit()
                
                # Redirect to a page where you can display GitHub account information
                return redirect('/index2')
            else:
                return 'Failed to fetch user data from GitHub'
        else:
            return 'Failed to obtain access token from GitHub'
    else:
        return 'GitHub authentication failed.'


@app.route('/profile')
def profile():
    github_user_data = session.get('github_user_data')
    if github_user_data:
        # Display user information here
        return f'GitHub User ID: {github_user_data["id"]}<br>GitHub Username: {github_user_data["login"]}'
    else:
        return 'User not authenticated.'
    
@app.route('/logout')
def logout():
    # Clear the session data

    # Redirect to the login page or any other page after logout
    return render_template('login_form.html')  # Change '/login_form' to the actual login page URL


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        app.run(debug=True)