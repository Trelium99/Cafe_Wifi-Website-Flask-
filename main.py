import os
from functools import wraps
from flask import Flask, render_template, url_for, redirect, abort, flash
from forms import AddCafeForm, RegisterForm, LoginForm
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy import Integer, String, Boolean
from flask_login import UserMixin, login_user, LoginManager, current_user, logout_user
from werkzeug.security import generate_password_hash, check_password_hash


app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ['SECRET']
login_manager = LoginManager()
login_manager.init_app(app)


@login_manager.user_loader
def load_user(user_id):
    return db.get_or_404(User, user_id)


class Base(DeclarativeBase):
    pass


app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///cafe_spots.db'
db = SQLAlchemy(model_class=Base)
db.init_app(app)


class CafeData(db.Model):
    __tablename__ = "Cafe_Data"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(250), unique=True, nullable=False)
    map_url: Mapped[str] = mapped_column(String(250), nullable=False)
    img_url: Mapped[str] = mapped_column(String(250), nullable=False)
    location: Mapped[str] = mapped_column(String(250), nullable=False)
    has_socket: Mapped[int] = mapped_column(Integer, nullable=False)
    has_toilet: Mapped[int] = mapped_column(Integer, nullable=False)
    has_wifi: Mapped[int] = mapped_column(Integer, nullable=False)
    can_take_calls: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    seats: Mapped[str] = mapped_column(String(250), nullable=False)
    coffee_price: Mapped[str] = mapped_column(String(250), nullable=False)


class User(UserMixin, db.Model):
    __tablename__ = "user_info"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(250), nullable=False)
    email: Mapped[str] = mapped_column(String(250), nullable=False, unique=True)
    password: Mapped[str] = mapped_column(String(250), nullable=False)


with app.app_context():
    db.create_all()


def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.id != 1:
            return abort(403)
        return f(*args, **kwargs)
    return decorated_function


def logged_in_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            flash("Login first to add cafe info.")
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


@app.route("/")
def home():
    result = db.session.execute(db.select(CafeData).order_by(CafeData.id))
    data = result.scalars().all()
    return render_template("index.html", table_data=data, current_user=current_user)


@app.route("/register", methods=["GET", "POST"])
def register_user():
    reg_form = RegisterForm()
    if reg_form.validate_on_submit():
        email = reg_form.user_email.data
        result = db.session.execute(db.select(User).where(User.email == email))
        user = result.scalar()
        if user:
            flash("This email already exists. Try logging in.")
            return redirect(url_for("login"))
        else:
            hashed_salted_password = generate_password_hash(reg_form.user_password.data,
                                                            method='pbkdf2:sha256',
                                                            salt_length=8)
            new_user = User(
                name=reg_form.user_name.data,
                email=reg_form.user_email.data,
                password=hashed_salted_password
            )
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user)
            return redirect(url_for("home"))
    return render_template("register.html", form=reg_form, current_user=current_user)


@app.route("/login", methods=["GET", "POST"])
def login():
    login_form = LoginForm()
    if login_form.validate_on_submit():
        email = login_form.login_email.data
        password = login_form.login_password.data
        result = db.session.execute(db.select(User).where(User.email == email))
        user = result.scalar()
        if not user:
            flash("This email is not registered to an account.")
            return redirect(url_for("login"))
        elif not check_password_hash(user.password, password):
            flash("Your password is incorrect.")
            return redirect(url_for("login"))
        else:
            login_user(user)
            return redirect(url_for("home"))
    return render_template("login.html", form=login_form, current_user=current_user)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('home'))


@app.route("/add", methods=["GET", "POST"])
@logged_in_only
def add_cafe():
    form = AddCafeForm()
    if form.validate_on_submit():
        new_entry = CafeData(
            name=form.cafe_name.data,
            map_url=form.map_url.data,
            img_url=form.img_url.data,
            location=form.location.data,
            has_socket=form.has_sockets.data,
            has_toilet=form.has_toilet.data,
            has_wifi=form.has_wifi.data,
            can_take_calls=form.can_take_calls.data,
            seats=form.seats.data,
            coffee_price=form.coffee_price.data
        )
        db.session.add(new_entry)
        db.session.commit()
        return redirect(url_for("home"))
    return render_template("add_cafe.html", form=form, current_user=current_user)


@app.route("/delete/<int:cafe_id>")
def delete_cafe(cafe_id):
    cafe_to_delete = db.get_or_404(CafeData, cafe_id)
    db.session.delete(cafe_to_delete)
    db.session.commit()
    return redirect(url_for('home'))


if __name__ == "__main__":
    app.run(debug=True)
