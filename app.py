from flask import Flask, render_template, request, redirect, url_for, flash, session
from passlib.handlers.sha2_crypt import sha256_crypt
from wtforms.validators import Length

from dbconn import connection
from wtforms import Form, TextField, validators, PasswordField

app = Flask(__name__)
app.secret_key = "898911"


@app.route('/')
def homepage():
    return render_template("index.html")


class RegistrationForm(Form):
    user_name = TextField('Username', [validators.Length(min=4, max=20)])
    email = TextField('Email', [validators.Length(min=4, max=50)])
    password = PasswordField('Password', [validators.InputRequired(),
                                          validators.equal_to('confirm', message='Password must match')])
    confirm = PasswordField('Repeat password')
    full_name = TextField('Full-name', [validators.Length(min=5, max=50)])
    address = TextField('Address', [validators.Length(min=5, max=250)])


@app.route('/register/', methods=['GET', 'POST'])
def register_page():
    try:
        form = RegistrationForm(request.form)

        if request.method == 'POST' and form.validate():
            user_name = form.user_name.data
            email = form.email.data
            password = sha256_crypt.encrypt(str(form.password.data))
            full_name = form.full_name.data
            address = form.address.data

            c, conn = connection()
            if c.execute('SELECT EXISTS (SELECT * FROM users WHERE user_name= %s)', [user_name]):
                flash('Username is taken')
                return render_template('register.html', form=form)
            else:
                c.execute('INSERT INTO users(user_name, password, name, address, email) VALUES (%s, %s, %s, %s, %s)',
                          (user_name, password, full_name, address, email))
                conn.commit()

                c.close()
                conn.close()
                session['logged-in'] = True
                session['user_name'] = user_name
                return redirect(url_for('homepage'))
        return render_template("register.html", form=form)

    except Exception as e:
        return str(e)


@app.route('/login/', methods=['GET', 'POST'])
def login_page():
    error = None
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
                return  redirect(url_for('homepage'))
            else:
                error = "Invalid"
        return render_template("login.html", error=error)

    except Exception as e:
        print(f"{e}")
        return render_template("login.html", error=error)


if __name__ == '__main__':
    app.debug = True
    app.run()
