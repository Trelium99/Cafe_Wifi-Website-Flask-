from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField, EmailField, IntegerField, BooleanField, FloatField
from wtforms.validators import DataRequired, URL, Email, Length, NumberRange


class AddCafeForm(FlaskForm):
    cafe_name = StringField("Cafe Name", validators=[DataRequired(), Length(1, 250)])
    map_url = StringField("Maps URL", validators=[DataRequired(), URL()])
    img_url = StringField("Cafe Image URL", validators=[DataRequired(), URL()])
    location = StringField("Area Name", validators=[DataRequired(), Length(1, 150)])
    has_sockets = IntegerField("Socket Rating", validators=[DataRequired(), NumberRange(0, 5)])
    has_toilet = IntegerField("Toilet Rating", validators=[DataRequired(), NumberRange(0, 5)])
    has_wifi = IntegerField("Wifi Rating", validators=[DataRequired(), NumberRange(0, 5)])
    can_take_calls = BooleanField("Will Take Calls?")
    seats = StringField("Number of Seats", validators=[DataRequired()])
    coffee_price = StringField("Coffee Price", validators=[DataRequired(message="Coffee Price field is required."), ])
    submit = SubmitField("Add Cafe")


class RegisterForm(FlaskForm):
    user_name = StringField("Your Name", validators=[DataRequired(), Length(1, 100)])
    user_email = EmailField("Your Email", validators=[DataRequired(), Email()])
    user_password = PasswordField("Your Password", validators=[DataRequired()])
    submit = SubmitField("register")


class LoginForm(FlaskForm):
    login_email = EmailField("Your Email", validators=[DataRequired(), Email()])
    login_password = PasswordField("Your Password", validators=[DataRequired()])
    submit = SubmitField("Login")
