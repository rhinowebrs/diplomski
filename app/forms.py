from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, FileField
from wtforms.fields.simple import BooleanField
from wtforms.validators import DataRequired, Email, EqualTo, ValidationError, Length, URL, Optional
from flask_wtf.file import FileAllowed
from .models import User
from flask_login import current_user

class LoginForm(FlaskForm):
    email = StringField('Username (or Email)', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    name = StringField('Full Name', validators=[DataRequired()])  # Added name field
    email = StringField(
        'Email',
        validators=[DataRequired(), Email(message='Invalid email address.')]
    )
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField(
        'Confirm Password',
        validators=[
            DataRequired(),
            EqualTo('password', message='Passwords must match.')
        ]
    )
    submit = SubmitField('Register')

    # Custom validator to check if email is unique
    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('This email is already registered. Please choose a different one.')

class AccountSettingsForm(FlaskForm):
    username = StringField(
        'Username',
        validators=[DataRequired(), Length(min=3, max=20)]
    )
    name = StringField(
        'Full Name',
        validators=[DataRequired(), Length(min=2, max=100)]
    )
    email = StringField(
        'Email',
        validators=[DataRequired(), Email(message='Invalid email address.')]
    )
    profile_picture = FileField(
        'Update Profile Picture',
        validators=[FileAllowed(['jpg', 'png', 'jpeg'], 'Images only!')]
    )
    password = PasswordField(
        'New Password (leave blank if not changing)',
        validators=[]
    )
    confirm_password = PasswordField(
        'Confirm New Password',
        validators=[
            EqualTo('password', message='Passwords must match.')
        ]
    )
    submit = SubmitField('Update Account')

    def validate_username(self, username):
        if username.data != current_user.username:
            user = User.query.filter_by(username=username.data).first()
            if user:
                raise ValidationError('This username is already taken. Please choose a different one.')

    def validate_email(self, email):
        if email.data != current_user.email:
            user = User.query.filter_by(email=email.data).first()
            if user:
                raise ValidationError('This email is already registered. Please choose a different one.')


class PasswordForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired()])
    url = StringField('URL', validators=[Optional(), URL()])
    no_url = BooleanField('No URL')
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8, message='Password must be at least 8 characters long.')])
    show_password = BooleanField('Show Password')
    submit = SubmitField('Save Password')

    def validate(self, extra_validators=None):
        rv = super().validate(extra_validators=extra_validators)
        # Cross-field rule: if "No URL" is not checked, URL is required
        if not self.no_url.data and (not self.url.data or not self.url.data.strip()):
            self.url.errors.append('URL is required unless "No URL" is checked.')
            return False
        return rv

    def validate_password(self, password):
        if len(password.data or '') < 8:
            raise ValidationError('Password must be at least 8 characters long.')
