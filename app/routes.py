from flask import Blueprint, render_template, redirect, url_for, flash, request
from flask_login import login_user

from app import db, bcrypt
from app.forms import RegisterForm, LoginForm
from app.models import User

main = Blueprint('main', __name__)

@main.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        new_user = User(
            username=form.username.data,
            email=form.email.data,
            password=form.password.data  # Hash this password
        )
        db.session.add(new_user)
        db.session.commit()
        flash('Account created successfully', 'success')
        return redirect(url_for('main.login'))
    return render_template('register.html', form=form)

@main.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        # Authentication logic here
        user = User.query.filter_by(email=form.email.data).first()
        if user and user.password == form.password.data:  # Replace with hashed password check
            login_user(user)
            return redirect(url_for('main.landing'))
        flash('Invalid credentials', 'danger')
    return render_template('login.html', form=form)

@main.route('/', methods=['GET', 'POST'])
def landing():
    return render_template('landing.html')
avb
