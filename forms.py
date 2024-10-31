from flask_wtf import FlaskForm
from wtforms import StringField, EmailField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, Length, Regexp, EqualTo

class RegistrationForm(FlaskForm):
    email = EmailField('Email', validators=[DataRequired(), Email(), Length(max=50)])
    name = StringField('Name', validators=[DataRequired(), Length(min=3, max=30), Regexp(r'^[a-zA-Z\s]+$', message="Name must only contain letters")])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Register')
