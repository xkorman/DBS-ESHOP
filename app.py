from functools import wraps

import psycopg2
from faker import Faker
from flask import Flask, render_template, request, redirect, url_for, flash, session
from passlib.handlers.sha2_crypt import sha256_crypt
from psycopg2._psycopg import IntegrityError

from dbconn import connection
from wtforms import Form, TextField, validators, PasswordField

app = Flask(__name__)
app.secret_key = "898911"


@app.route('/')
def homepage():
    return render_template("index.html")


class RegistrationForm(Form):
    user_name = TextField('Username', [validators.Length(min=4, max=20)])
    email = TextField('Email', [validators.Length(min=5, max=249),
                                validators.Email()])
    password = PasswordField('Password', [validators.InputRequired(),
                                          validators.equal_to('confirm', message='Password must match')])
    confirm = PasswordField('Repeat password')
    full_name = TextField('Full-name', [validators.Length(min=5, max=50)])
    address = TextField('Address', [validators.Length(min=5, max=250)])


@app.route('/register/', methods=['GET', 'POST'])
def register_page():
    form = RegistrationForm(request.form)
    try:

        if request.method == 'POST' and form.validate():
            user_name = form.user_name.data
            email = form.email.data
            password = sha256_crypt.encrypt(str(form.password.data))
            full_name = form.full_name.data
            address = form.address.data

            c, conn = connection()

            c.execute('INSERT INTO users(user_name, password, name, address, email) VALUES (%s, %s, %s, %s, %s)',
                      (user_name, password, full_name, address, email))
            conn.commit()

            c.close()
            conn.close()
            session['logged-in'] = True
            session['user_name'] = user_name
            return redirect(url_for('homepage'))
        return render_template("register.html", form=form)

    except IntegrityError:
        flash("Username already used")
        return render_template("register.html", form=form)
    except Exception as e:
        flash(f"{e}")
        return render_template("register.html", form=form)


def login_required(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'logged-in' in session:
            return f(*args, **kwargs)
        else:
            flash("Log in first!")
            return redirect(url_for('login_page'))

    return wrap


@app.route("/logout/")
@login_required
def logout():
    session.clear()
    flash("Logged out")
    return redirect(url_for('homepage'))


@app.route('/login/', methods=['GET', 'POST'])
def login_page():
    try:
        c, conn = connection()
        if request.method == "POST":

            data = c.execute("SELECT * FROM users WHERE user_name = %s", [request.form['username']])
            data = c.fetchone()[2]
            print(f"{data}")

            if sha256_crypt.verify(request.form['password'], data):
                session['logged-in'] = True
                session['user_name'] = request.form['username']

                flash("Logged in")
                return redirect(url_for('homepage'))
            else:
                flash("Invalid username or password")
        return render_template("login.html")

    except TypeError:
        flash("Nic si nezadal")
        return render_template("login.html")
    except Exception as e:
        flash(e)
        return render_template("login.html")


@app.route('/products/')
def products_page():
    products = None
    try:
        c, conn = connection()
        c.execute("SELECT * FROM product")
        products = c.fetchall()
        return render_template("products.html", products=products)

    except Exception as e:
        flash(e)
        return render_template("products.html", products=products)


# def do_faker():
#     faker = Faker('cz_CZ')
#     print(f"{faker.region(), faker.address(), faker.email()}")
#
#
# do_faker()


if __name__ == '__main__':
    app.debug = True
    app.run()
