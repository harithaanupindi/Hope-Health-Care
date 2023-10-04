from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from oauthlib.oauth2 import WebApplicationClient
from flask_oauthlib.client import OAuth
from werkzeug.security import generate_password_hash, check_password_hash 

app = Flask(__name__)
app.secret_key = '38984c9a11888697f6b274d3e52e8f53'

# Configure your SQLAlchemy database URI here
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:Hillgrange@localhost:5433/Registration'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy()
db.init_app(app)
migrate = Migrate(app, db)

oauth = OAuth(app)
google = oauth.remote_app(
    'google',
    consumer_key='497561493859-2l1rqnevoccrlti4hpnll1afqmlvkct1.apps.googleusercontent.com',
    consumer_secret='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',
    request_token_params={
        'scope': 'email profile openid', # Adjust the scope as needed
    },
    base_url='https://www.googleapis.com/oauth2/v1/',
    request_token_url=None,
    access_token_method='POST',
    access_token_url='https://accounts.google.com/o/oauth2/token',
    authorize_url='https://accounts.google.com/o/oauth2/auth',
)

from models import User, Registration
from models import User, Registration
migrate = Migrate(app, db)

@app.route('/')
def index():
    return render_template('base.html')

@app.route('/register', methods=['GET', 'POST'])
def register_user():
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        phone = request.form.get('phone')

        # Create a Registration instance and add it to the database
        registration = Registration(name=name, email=email, phone=phone)

        try:
            db.session.add(registration)
            db.session.commit()
            return redirect(url_for('thank_you'))  # Redirect to the thank you page
        except Exception as e:
            db.session.rollback()
            print("Error:", str(e))
            return "An error occurred while saving the data."

    # Handle GET requests or errors by rendering the registration form again
    return render_template('registrations.html')

@app.route('/thank_you')
def thank_you():
    return render_template('thankyou.html')
@app.route('/contact')
def contact():
    return render_template('contact.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # Get user input (email and password)
        email = request.form.get('email')
        password = request.form.get('password')

        # Authenticate the user (You should implement this logic)
        if authenticate_user(email, password):
            # Set a session variable to indicate the user is logged in
            session['user_email'] = email
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))  # Redirect to a dashboard page
        else:
            flash('Invalid email or password. Please try again.', 'error')

    return render_template('login.html')

# Implement the authenticate_user function as per your needs
def authenticate_user(email, password):
    # Implement user authentication logic here (e.g., check credentials against a database)
    # Return True if authentication is successful, otherwise return False
    # Example:
    # if email == 'user@example.com' and password == 'password':
    #     return True
    # else:
    #     return False
    pass

# Define a route for the dashboard page (to be created)
@app.route('/dashboard')
def dashboard():
    # Check if the user is logged in (You can use session['user_email'])
    if 'user_email' in session:
        return render_template('dashboard.html')
    else:
        flash('You must be logged in to access the dashboard.', 'error')
        return redirect(url_for('login'))

@app.route('/google_authorized')
def google_authorized():
    response = google.authorized_response()

    if response is None or response.get('access_token') is None:
        return 'Access denied: reason={} error={}'.format(
            request.args['error_reason'],
            request.args['error_description']
        )

    # Fetch user information from Google
    user_info = google.get('userinfo')
    google_email = user_info.data['email']
    name = user_info.data['name']

    # Check if the user already exists in the database
    user = User.query.filter_by(google_email=google_email).first()

    if not user:
        # User doesn't exist, create a new user record
        user = User(google_email=google_email, name=name)
        db.session.add(user)
        db.session.commit()

    # Store the user's email in the session
    session['user_email'] = google_email

    # Redirect to the user-specific page or perform other actions as needed
    return redirect(url_for('user_dashboard'))
@google.tokengetter
def get_oauth_token():
    return session.get('google_token')
@app.route('/some_protected_route')
def some_protected_route():
    oauth_token = session.get('oauth_token')
    if oauth_token:
    
        api_response = make_authenticated_api_request(oauth_token)

        # Process the API response and return a result
        return 'API Response: {}'.format(api_response)
    else:
        # The user is not authenticated, handle accordingly
        return 'Access denied: User is not authenticated'


if __name__ == '__main__':
    app.run(debug=True)