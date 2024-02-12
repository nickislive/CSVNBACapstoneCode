import os
import pandas as pd
import matplotlib.pyplot as plt
import base64
import io
from flask import Flask, render_template, request, redirect, url_for, flash, session, send_from_directory, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import requests

# Initialization
app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key_here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['UPLOAD_FOLDER'] = './uploads'
app.config['ALLOWED_EXTENSIONS'] = {'csv'}

# Ensure the upload folder exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Database setup
db = SQLAlchemy(app)

# Login manager setup
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# User model
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)

# Load user for login manager
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Helper functions
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

# Helper function to plot data based on column selections
def plot_csv_data(filepath, column_name_1, column_name_2):
    df = pd.read_csv(filepath)
    plt.switch_backend('Agg')
    grouped = df.groupby([column_name_1, column_name_2]).size().unstack()
    grouped.plot(kind='bar', stacked=True)
    plt.subplots_adjust(bottom=0.2)  # Adjust the bottom margin to provide more space for labels
    img = io.BytesIO()
    plt.savefig(img, format='png', bbox_inches="tight")  # Use bbox_inches to fit the entire plot area
    img.seek(0)
    plt.close()
    return base64.b64encode(img.getvalue()).decode('utf-8')

# Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            login_user(user, remember=True)
            next_page = request.args.get('next')
            return redirect(next_page or url_for('index'))
        flash('Invalid username or password')
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user:
            flash('Username already exists.')
            return redirect(url_for('signup'))
        hashed_password = generate_password_hash(password, method='sha256')
        new_user = User(username=username, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        flash('Your account has been created, you are now able to log in.')
        return redirect(url_for('login'))
    return render_template('signup.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload_file():
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file part')
            return redirect(request.url)
        file = request.files['file']
        if file.filename == '' or not allowed_file(file.filename):
            flash('Invalid file type.')
            return redirect(request.url)
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        return redirect(url_for('view_data', filename=filename))
    return render_template('upload.html')

@app.route('/uploads/<filename>')
@login_required
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/data/<filename>', methods=['GET', 'POST'])
@login_required
def view_data(filename):
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    df = pd.read_csv(filepath)
    columns = df.columns.tolist()
    if request.method == 'POST':
        column_name_1 = request.form.get('column_name_1')
        column_name_2 = request.form.get('column_name_2')
        plot_url = plot_csv_data(filepath, column_name_1, column_name_2)
        return render_template('view_data.html', plot_url=plot_url, columns=columns, filename=filename)
    return render_template('view_data.html', columns=columns, filename=filename)

@app.route('/nba_data')
@login_required
def nba_data():
    response = requests.get('https://www.balldontlie.io/api/v1/players')
    if response.status_code == 200:
        return response.json()['data']
    else:
        return []
    
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
