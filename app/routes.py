from flask import Blueprint, render_template, redirect, url_for, flash, request, Response
from flask_login import login_user, login_required, logout_user, current_user
from wtforms.validators import ValidationError

from app import db, bcrypt
from app.forms import RegisterForm, LoginForm
from app.models import User

from sqlalchemy import or_


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
                    name=form.name.data,  # Added name field
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
                flash(f"{error}", 'danger')

    return render_template('register.html', form=form)


@main.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        # Attempt to find user by email OR username
        user = User.query.filter(
            or_(User.email == form.email.data, User.username == form.email.data)
        ).first()

        # Check if the user was found
        if user:
            # Compare provided password with the hashed password in DB
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)
                flash('Logged in successfully!', 'success')
                return redirect(url_for('main.landing'))
            else:
                flash('Password incorrect.', 'danger')
        else:
            flash('No account found with this email/username.', 'danger')

    elif form.errors:
        for field, error_messages in form.errors.items():
            for err in error_messages:
                flash(f'{err}', 'danger')

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

@main.route('/passwords')
@login_required
def passwords():
    return render_template('passwords.html', username=current_user.username)

@main.route('/account-settings')
@login_required
def account_settings():
    return render_template('account_settings.html', username=current_user.username)

@main.route('/profile_picture/<int:user_id>')
def profile_picture(user_id):
    user = User.query.get(user_id)
    if user and user.profile_picture:
        return Response(user.profile_picture, mimetype='image/png')  # Adjust mimetype if needed
    else:
        with open("app/static/img/blank-profile-picture.png", "rb") as f:
            default_img = f.read()
        return Response(default_img, mimetype='image/jpeg')