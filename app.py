import os
from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from werkzeug.security import generate_password_hash, check_password_hash
import matplotlib.pyplot as plt
import io
import base64
from datetime import datetime

# Application Configuration
app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)  # Secure secret key generation
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///carbon_tracker.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Database Initialization
db = SQLAlchemy(app)
migrate = Migrate(app, db)

# User Model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    footprint_calculations = db.relationship('FootprintCalculation', backref='user', lazy=True)

# Footprint Calculation Model
class FootprintCalculation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    activity = db.Column(db.String(100), nullable=False)
    carbon_emission = db.Column(db.Float, nullable=False)
    date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

# Route Handlers
@app.route('/')
def home():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password, password):
            session['username'] = username
            session['user_id'] = user.id
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password. Please try again.', 'danger')

    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Username already exists. Please choose a different one.', 'danger')
            return redirect(url_for('signup'))

        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = User(username=username, password=hashed_password)
        
        try:
            db.session.add(new_user)
            db.session.commit()
            flash('Account created successfully! Please log in.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            flash('An error occurred. Please try again.', 'danger')

    return render_template('signup.html')

@app.route('/dashboard')
def dashboard():
    if 'username' in session:
        return render_template('dashboard.html')
    else:
        flash('Please log in to access the dashboard.', 'danger')
        return redirect(url_for('login'))

@app.route('/calculator', methods=['GET', 'POST'])
def calculator():
    if 'username' not in session:
        flash('Please log in to access the calculator.', 'danger')
        return redirect(url_for('login'))

    if request.method == 'POST':
        try:
            # Extract form data
            electricity = float(request.form['electricity'])
            car_travel = float(request.form['car_travel'])
            air_travel = float(request.form['air_travel'])
            food = request.form['food']
            waste = float(request.form['waste'])

            # Carbon Footprint Calculation Logic
            carbon_emission = 0
            carbon_emission += electricity * 0.92
            carbon_emission += car_travel * 0.21
            carbon_emission += air_travel * 0.15

            # Food impact
            if food == "meat":
                carbon_emission += 5
            elif food == "vegetarian":
                carbon_emission += 2.5

            carbon_emission += waste * 0.01

            # Save calculation
            user_id = session.get('user_id')
            new_calculation = FootprintCalculation(
                user_id=user_id, 
                activity='Daily Activities', 
                carbon_emission=carbon_emission
            )
            
            db.session.add(new_calculation)
            db.session.commit()

            flash(f'Your total carbon footprint is: {carbon_emission:.2f} kg CO2', 'success')
            return redirect(url_for('dashboard'))
        
        except ValueError:
            flash('Please enter valid numbers for the activities.', 'danger')

    return render_template('calculator.html')

@app.route('/track_progress')
def track_progress():
    if 'username' not in session:
        flash('Please log in to access your progress.', 'danger')
        return redirect(url_for('login'))

    user_id = session.get('user_id')
    calculations = FootprintCalculation.query.filter_by(user_id=user_id).order_by(FootprintCalculation.date.desc()).all()

    # Create the histogram for carbon emissions
    if calculations:
        emissions = [calc.carbon_emission for calc in calculations]

        plt.figure(figsize=(8, 6))
        plt.hist(emissions, bins=10, color='skyblue', edgecolor='black')
        plt.title('Carbon Emission Over Time')
        plt.xlabel('Carbon Emission (kg CO2)')
        plt.ylabel('Frequency')

        # Save the plot to a BytesIO object and encode it in base64
        img = io.BytesIO()
        plt.savefig(img, format='png')
        plt.close()
        img.seek(0)
        plot_url = base64.b64encode(img.getvalue()).decode('utf8')

        return render_template('progress.html', calculations=calculations, plot_url=plot_url)
    
    return render_template('progress.html', calculations=[], plot_url=None)

@app.route('/tips')
def tips():
    if 'username' in session:
        return render_template('tips.html')
    else:
        flash('Please log in to access the tips.', 'danger')
        return redirect(url_for('login'))

@app.route('/logout')
def logout():
    session.pop('username', None)
    session.pop('user_id', None)
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

# Error Handling
@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_server_error(e):
    return render_template('500.html'), 500

# Application Entry Point
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)

# Requirements (requirements.txt):
# flask
# flask-sqlalchemy
# flask-migrate
# werkzeug
# matplotlib