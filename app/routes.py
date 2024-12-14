from flask import Blueprint, render_template, redirect, url_for, flash, request
from flask_login import login_user, login_required, logout_user, current_user
from wtforms.validators import ValidationError

from app import db, bcrypt
from app.forms import RegisterForm, LoginForm
from app.models import User

main = Blueprint('main', __name__)


@main.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        # Check if username or email already exists
        existing_user_by_username = User.query.filter_by(username=form.username.data).first()
        if existing_user_by_username:
            flash('Username already exists. Please choose a different one.', 'danger')
        else:
            try:
                form.validate_email(form.email)
                # Proceed to create a new user
                hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
                new_user = User(
                    username=form.username.data,
                    email=form.email.data,
                    password=hashed_password
                )
                db.session.add(new_user)
                db.session.commit()
                flash('Account created successfully', 'success')
                return redirect(url_for('main.login'))
            except ValidationError as e:
                flash(str(e), 'danger')
    else:
        # Flash validation errors
        for field, error_messages in form.errors.items():
            for error in error_messages:
                flash(f"{field.capitalize()} Error: {error}", 'danger')

    return render_template('register.html', form=form)



@main.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)
                flash('Logged in successfully!', 'success')
                return redirect(url_for('main.landing'))
            else:
                flash('Password incorrect.', 'danger')
        else:
            flash('No account found with this email. Please check the email address.', 'danger')
    elif form.errors:
        for field, error_messages in form.errors.items():
            for err in error_messages:
                flash(f'{field.capitalize()} Error: {err}', 'danger')

    return render_template('login.html', form=form)


@main.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('main.login'))

@main.route('/')
@login_required
def landing():
    return render_template('landing.html', username=current_user.username)
