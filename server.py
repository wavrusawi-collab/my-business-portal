import os
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SECRET_KEY'] = 'professional-business-secret-key'
# Database setup: SQLite file business_app.db
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///business_app.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# Models
class Company(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    users = db.relationship('User', backref='company', lazy=True)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), nullable=False)
    password = db.Column(db.String(200), nullable=False)
    company_id = db.Column(db.Integer, db.ForeignKey('company.id'), nullable=False)

# Create the database and tables
with app.app_context():
    db.create_all()

@app.route('/')
def index():
    companies = Company.query.all()
    return render_template('index.html', companies=companies)

@app.route('/create_company', methods=['POST'])
def create_company():
    company_name = request.form.get('company_name')
    if not company_name:
        flash('Company name is required', 'error')
        return redirect(url_for('index'))
    
    existing = Company.query.filter_by(name=company_name).first()
    if existing:
        flash('Company already exists', 'error')
    else:
        new_company = Company(name=company_name)
        db.session.add(new_company)
        db.session.commit()
        flash(f'Company "{company_name}" created successfully!', 'success')
    
    return redirect(url_for('index'))

@app.route('/create_account', methods=['POST'])
def create_account():
    company_id = request.form.get('company_id')
    username = request.form.get('username')
    password = request.form.get('password')
    
    if not all([company_id, username, password]):
        flash('All fields are required', 'error')
        return redirect(url_for('index'))
    
    hashed_pw = generate_password_hash(password, method='pbkdf2:sha256')
    new_user = User(username=username, password=hashed_pw, company_id=company_id)
    
    try:
        db.session.add(new_user)
        db.session.commit()
        flash('Account created successfully! Please sign in.', 'success')
    except Exception as e:
        db.session.rollback()
        flash('Error creating account.', 'error')
        
    return redirect(url_for('index'))

@app.route('/login', methods=['POST'])
def login():
    company_id = request.form.get('company_id')
    username = request.form.get('username')
    password = request.form.get('password')
    
    user = User.query.filter_by(username=username, company_id=company_id).first()
    
    if user and check_password_hash(user.password, password):
        return render_template('dashboard.html', user=user)
    
    flash('Invalid username or password for this company.', 'error')
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)