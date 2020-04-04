import os
from datetime import date
from functools import wraps

from faker import Faker
from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_wtf.file import FileAllowed, FileRequired, FileField
from passlib.handlers.sha2_crypt import sha256_crypt
from psycopg2._psycopg import IntegrityError
from werkzeug.utils import secure_filename

from dbconn import connection
from wtforms import Form, TextField, validators, PasswordField, StringField, BooleanField, IntegerField, TextAreaField, \
    FileField, SelectField

UPLOAD_FOLDER = 'static/images/products/'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

app = Flask(__name__)
app.secret_key = "898911"
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER


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


class DashUserForm(Form):
    nick = StringField('Nick', [validators.length(min=4, max=20)])
    full_name = StringField('Fullname', [validators.length(min=5, max=250)])
    email = StringField('Email', [validators.Length(min=5, max=249),
                                  validators.Email()])
    newPass = PasswordField('New password', [validators.equal_to('confirmnew', message='Passwords must match')])
    confirmnew = PasswordField('Repeat new password')
    address = StringField('Address', [validators.Length(min=5, max=250)])
    admin = BooleanField('Admin permission')


class AddProductForm(Form):
    product_name = StringField('Product name', [validators.Length(min=1, max=250)])
    product_price = IntegerField('Price', [validators.NumberRange(min=0)])
    product_description = TextAreaField('Description', render_kw={"rows": 10})
    product_image = FileField('photo', validators=[FileAllowed(['png', 'pdf', 'jpg'], "wrong format!")])
    bid = SelectField('Select brand', choices=[], coerce=int, default=1)
    cid = SelectField('Select category', choices=[], coerce=int, default=1)


class AddBrandForm(Form):
    brand_name = StringField('Brand name', [validators.Length(min=1, max=250)])
    quality = IntegerField('Quality')
    brand_description = TextAreaField('Description', render_kw={"rows": 10})


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
            session['user_id'] = user_name
            session['admin'] = 0

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


def admin_required(f):
    @wraps(f)
    def admin_control(*args, **kwargs):
        c, conn = connection()

        c.execute("SELECT permission FROM users WHERE user_name='%s'" % session['user_name'])
        if c.fetchone()[0]:
            return f(*args, **kwargs)
        else:
            flash("You have to be admin")
            return redirect(url_for('products_page'))

    return admin_control


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

            c.execute("SELECT * FROM users WHERE user_name = %s", [request.form['username']])
            data = c.fetchone()

            if sha256_crypt.verify(request.form['password'], data[2]):
                session['logged-in'] = True
                session['user_name'] = request.form['username']
                session['user_id'] = data[0]
                session['admin'] = data[6]

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
        c.execute("SELECT * FROM product ORDER BY product_id")
        products = c.fetchall()
        return render_template("products.html", products=products)

    except Exception as e:
        flash(e)
        return render_template("products.html", products=products)


@app.route('/dashboard/')
@login_required
@admin_required
def dashboard_page():
    return render_template("dashboard.html")


@app.route('/dashboard/orders/')
@login_required
@admin_required
def dash_order_page():
    c, conn = connection()
    query_orders = 'SELECT "order".*, users.id, users.user_name FROM "order" INNER JOIN users ON user_id=id '
    c.execute(query_orders)
    order_list = c.fetchall()
    return render_template("dash_orders.html", orders=order_list)


@app.route('/dashboard/products/')
@login_required
@admin_required
def dash_products_page():
    c, conn = connection()

    query_orders = 'SELECT "product".*, brand_name, category_name FROM product ' \
                   'INNER JOIN brand ON bid=brand_id ' \
                   'INNER JOIN category ON  cid=category_id ORDER BY product.product_id'
    c.execute(query_orders)
    products_list = c.fetchall()
    return render_template("dash_products.html", products=products_list)


@app.route('/dashboard/users/', methods=['GET', 'POST'])
@login_required
@admin_required
def dash_users_page():
    c, conn = connection()

    query_orders = 'SELECT * FROM users ORDER BY id'
    c.execute(query_orders)
    users_list = c.fetchall()

    return render_template('dash_users.html', users=users_list)


@app.route('/dashboard/users/<user_id>/', methods=['GET', 'POST'])
@login_required
@admin_required
def dash_users_page_id(user_id):
    form = DashUserForm(request.form)

    c, conn = connection()

    c.execute('SELECT * FROM users WHERE id=%s', [user_id])
    user = c.fetchone()

    try:

        if request.method == 'POST' and form.validate() and request.form['buttonpost'] == 'update':
            user_name = form.nick._value()
            email = form.email.data
            password = sha256_crypt.encrypt(str(form.newPass.data))
            full_name = form.full_name.data
            address = form.address.data
            admin = form.admin.data

            c, conn = connection()

            if password == '':
                c.execute('UPDATE users SET name=%s, address=%s, email=%s permission=%s WHERE user_name=%s',
                          (full_name, address, email, admin, user_name))
            else:
                c.execute('UPDATE users SET password = %s, name=%s, address=%s, email=%s, permission=%s '
                          'WHERE user_name=%s', (password, full_name, address, email, admin, user_name))
            conn.commit()

            c.close()
            conn.close()

            return redirect(url_for('dash_users_page'))

        elif request.method == 'POST' and request.form['buttonpost'] == 'delete':
            c, conn = connection()
            c.execute('DELETE FROM users WHERE id=%s', [user[0]])
            conn.commit()
            c.close()
            conn.close()
            return redirect(url_for('dash_users_page'))
        else:
            return render_template("dash_user_update.html", user=user, form=form)
    except Exception as e:
        flash(f"{e}")
        return render_template("dash_user_update.html", user=user, form=form)


def get_brands():
    c, conn = connection()
    choices = []

    c.execute('SELECT brand_id, brand_name FROM brand')

    for row in c.fetchall():
        choices += [(str(row[0]), str(row[1]))]

    c.close()
    conn.close()
    return choices


def get_categories():
    c, conn = connection()
    choices = []

    c.execute('SELECT category_id, category_name FROM category')

    for row in c.fetchall():
        choices += [(str(row[0]), str(row[1]))]

    c.close()
    conn.close()
    return choices


@app.route('/dashboard/products/add/', methods=['GET', 'POST'])
@login_required
@admin_required
def dash_product_add():
    form = AddProductForm(request.form)
    form.bid.choices = get_brands()
    form.cid.choices = get_categories()

    c, conn = connection()

    try:

        if request.method == 'POST':

            product_name = form.product_name.data
            price = form.product_price.data
            product_description = form.product_description.data
            file = request.files['product_image']
            if file is not None:
                filename = secure_filename(file.filename)
                pathname = '/static/images/products/' + filename
            else:
                pathname = ''
            bid = form.bid.data
            cid = form.cid.data

            c.execute(
                'INSERT INTO product(product_name, product_price, product_description, product_image, bid, cid) '
                'VALUES (%s, %s, %s, %s, %s, %s)',
                (product_name, int(price), product_description, pathname, int(bid), int(cid)))
            conn.commit()

            flash("Product has been added")
            if file.filename is not '':
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

            c.close()
            conn.close()

            return redirect(url_for('dash_products_page'))
        return render_template("dash_products_add.html", form=form)
    except Exception as e:
        flash(f"{e}")
        print(f"{e}")
        return render_template("dash_products_add.html", form=form)


@app.route('/dashboard/products/<product_id>/', methods=['GET', 'POST'])
@login_required
@admin_required
def dash_product_page_id(product_id):
    form = AddProductForm(request.form)

    c, conn = connection()

    c.execute('SELECT * FROM product WHERE product_id=%s', [product_id])

    product = c.fetchone()
    form.bid.choices = get_brands()
    form.bid.default = product[5]
    form.cid.choices = get_categories()
    form.cid.default = product[6]

    try:

        if request.method == 'POST' and request.form['buttonpost'] == 'update':

            product_name = form.product_name.data
            price = form.product_price._value()
            product_description = form.product_description.data
            file = request.files['product_image']
            bid = form.bid.data
            cid = form.cid.data

            if file.filename is not '':
                filename = secure_filename(file.filename)
                pathname = '/static/images/products/' + filename

                c.execute('UPDATE product SET product_name = %s, product_price=%s, product_description=%s, '
                          'product_image=%s, bid=%s, cid=%s '
                          'WHERE product_id=%s', (product_name, price, product_description, pathname, bid, cid,
                                                  product[0]))
            else:

                c.execute('UPDATE product SET product_name = %s, product_price=%s, product_description=%s, '
                          'bid=%s, cid=%s '
                          'WHERE product_id=%s', (product_name, price, product_description, bid, cid, product[0]))

            conn.commit()

            c.close()
            conn.close()

            return redirect(url_for('dash_products_page'))

        elif request.method == 'POST' and request.form['buttonpost'] == 'delete':
            c, conn = connection()
            c.execute('DELETE FROM product WHERE product_id=%s', [product_id])
            conn.commit()
            c.close()
            conn.close()
            return redirect(url_for('dash_products_page'))
        else:
            form.process()

            return render_template("dash_products_update.html", product=product, form=form)
    except Exception as e:
        flash(f"{e}")
        form.process()

        return render_template("dash_products_update.html", product=product, form=form)


@app.route('/dashboard/brands/')
@login_required
@admin_required
def dash_brands_page():
    c, conn = connection()

    query_orders = 'SELECT * FROM brand ORDER BY brand_id'
    c.execute(query_orders)
    brand_list = c.fetchall()
    return render_template("dash_brands.html", brands=brand_list)


@app.route('/dashboard/brands/add/', methods=['GET', 'POST'])
@login_required
@admin_required
def dash_brand_add():
    form = AddBrandForm(request.form)
    c, conn = connection()

    try:

        if request.method == 'POST' and form.validate():

            brand_name = form.brand_name.data
            quality = form.quality._value()
            brand_description = form.brand_description.data
            print(f"{brand_name, brand_description, quality}")

            c.execute('INSERT INTO brand(brand_name, quality, description) VALUES (%s, %s, %s)',
                      (brand_name, quality, brand_description))

            conn.commit()

            c.close()
            conn.close()

            return redirect(url_for('dash_brands_page'))

        return render_template("dash_brands_add.html", form=form)

    except Exception as e:
        flash(f"{e}")
        form.process()

        return render_template("dash_brands_add.html", form=form)


@app.route('/dashboard/brands/<brand_id>/', methods=['GET', 'POST'])
@login_required
@admin_required
def dash_brand_page_id(brand_id):
    form = AddBrandForm(request.form)

    c, conn = connection()

    c.execute('SELECT * FROM brand WHERE brand_id=%s', [brand_id])
    brand = c.fetchone()

    try:

        if request.method == 'POST' and request.form['buttonpost'] == 'update':

            brand_name = form.brand_name.data
            quality = form.quality._value()
            brand_description = form.brand_description.data

            c.execute('UPDATE brand SET brand_name = %s, quality=%s, description=%s '
                      'WHERE brand_id=%s', (brand_name, quality, brand_description, brand[0]))

            conn.commit()

            c.close()
            conn.close()

            return redirect(url_for('dash_brands_page'))

        elif request.method == 'POST' and request.form['buttonpost'] == 'delete':
            c, conn = connection()
            c.execute('DELETE FROM brand WHERE brand_id=%s', [brand_id])
            conn.commit()
            c.close()
            conn.close()
            return redirect(url_for('dash_brands_page'))
        else:
            form.process()

            return render_template("dash_brands_update.html", brand=brand, form=form)
    except Exception as e:
        flash(f"{e}")
        form.process()

        return render_template("dash_brands_update.html", brand=brand, form=form)


@app.route('/dashboard/categories/')
@login_required
@admin_required
def dash_categories_page():
    c, conn = connection()

    query_orders = 'SELECT * FROM category ORDER BY category_id'
    c.execute(query_orders)
    category_list = c.fetchall()
    return render_template("dash_categories.html", categories=category_list)


@app.route('/dashboard/categories/add/', methods=['GET', 'POST'])
@login_required
@admin_required
def dash_category_add():
    form = AddBrandForm(request.form)
    c, conn = connection()

    try:

        if request.method == 'POST' and form.validate():

            brand_name = form.brand_name.data
            brand_description = form.brand_description.data

            c.execute('INSERT INTO category(category_name, description) VALUES (%s, %s)',
                      (brand_name, brand_description))

            conn.commit()

            c.close()
            conn.close()

            return redirect(url_for('dash_categories_page'))
        return render_template("dash_categories_add.html", form=form)

    except Exception as e:
        flash(f"{e}")
        form.process()

        return render_template("dash_categories_add.html", form=form)


@app.route('/dashboard/categories/<category_id>/', methods=['GET', 'POST'])
@login_required
@admin_required
def dash_category_page_id(category_id):
    form = AddBrandForm(request.form)

    c, conn = connection()

    c.execute('SELECT * FROM category WHERE category_id=%s', [category_id])
    brand = c.fetchone()

    try:

        if request.method == 'POST' and request.form['buttonpost'] == 'update':

            brand_name = form.brand_name.data
            brand_description = form.brand_description.data

            c.execute('UPDATE category SET category_name = %s, description=%s '
                      'WHERE category_id=%s', (brand_name, brand_description, category_id))

            conn.commit()

            c.close()
            conn.close()

            return redirect(url_for('dash_categories_page'))

        elif request.method == 'POST' and request.form['buttonpost'] == 'delete':
            c, conn = connection()
            c.execute('DELETE FROM category WHERE category_id=%s', [category_id])
            conn.commit()
            c.close()
            conn.close()
            return redirect(url_for('dash_categories_page'))
        else:
            form.process()

            return render_template("dash_categories_update.html", category=brand, form=form)
    except Exception as e:
        flash(f"{e}")
        form.process()

        return render_template("dash_categories_update.html", category=brand, form=form)


@app.route('/cart/')
@login_required
def cart_page():
    products = None
    c, conn = connection()

    c.execute('SELECT * FROM "order" WHERE user_id=%s AND open=True' % session['user_id'])
    orders = c.fetchone()

    if orders is not None:
        id = orders[0]
        query_orders = ('SELECT order_item.*, product.product_name, product.product_price, product.product_image, '
                        'category.category_name FROM order_item '
                        'INNER JOIN product ON order_item.product_id=product.product_id '
                        'INNER JOIN category ON product.cid=category.category_id WHERE order_id = %s ORDER BY product.product_id' % id)
        c.execute(query_orders)
        product_list = c.fetchall()
        return render_template("cart.html", products=product_list, order_info=orders)
    else:
        return render_template("cart.html", products=products, order_info=orders)


@app.route('/cart/update', methods=['POST'])
@login_required
def cart_update_count():
    c, conn = connection()
    count = request.form['count']
    id = request.form['order_item_id']
    try:
        if request.method == 'POST':

            if count != '0':
                c.execute('UPDATE order_item SET "count"=%s WHERE order_item_id=%s', (count, id))
            else:
                c.execute('DELETE FROM order_item WHERE order_item_id=%s', [id])

            conn.commit()
            c.close()
            conn.close()
        return redirect(url_for('cart_page'))
    except Exception as e:
        flash(f"{e}")
        return redirect(url_for('cart_page'))


@app.route('/cart/confirm', methods=['POST'])
@login_required
def cart_confirm():
    c, conn = connection()

    try:
        if request.method == 'POST':

            c.execute('UPDATE "order" SET "date"=%s, price=%s, "open"=%s WHERE order_id=%s',
                      (date.today().strftime('%Y/%m/%d'), request.form['price_of_order'], False,
                       request.form['order_id']))

            conn.commit()
            c.close()
            conn.close()
            flash("Ordered")
        return redirect(url_for('cart_page'))
    except Exception as e:
        flash(f"{e}")
        return redirect(url_for('cart_page'))

# def do_faker():
#     faker = Faker('cz_CZ')
#     print(f"{faker.region(), faker.address(), faker.email()}")
#
#
# do_faker()


if __name__ == '__main__':
    app.debug = True
    app.run()
