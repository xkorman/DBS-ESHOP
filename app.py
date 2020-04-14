import datetime
import json

import os
import random
from datetime import date, timedelta
from functools import wraps

from PIL import Image
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


class RegistrationForm(Form):
    user_name = TextField('Username', [validators.Length(min=4, max=20)])
    email = TextField('Email', [validators.Length(min=5, max=249),
                                validators.Email()])
    password = PasswordField('Password', [validators.InputRequired(),
                                          validators.equal_to('confirm', message='Password must match')])
    confirm = PasswordField('Repeat password')
    full_name = TextField('Full-name', [validators.Length(min=5, max=50)])
    zip = StringField(u'Select ZIP code', [validators.required(), validators.length(min=5, max=6)])
    address = TextField('Address', [validators.Length(min=5, max=250)])


class DashUserForm(Form):
    nick = StringField('Nick', [validators.length(min=4, max=20)])
    full_name = StringField('Fullname', [validators.length(min=5, max=250)])
    email = StringField('Email', [validators.Length(min=5, max=249),
                                  validators.Email()])
    newPass = PasswordField('New password', [validators.equal_to('confirmnew', message='Passwords must match')])
    confirmnew = PasswordField('Repeat new password')
    city = StringField(u'Select ZIP code', [validators.required(), validators.length(min=5, max=6)])
    address = TextField('Address', [validators.Length(min=5, max=250)])
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


class FindName(Form):
    find_name = StringField('Name', [validators.required()])


@app.route('/register/', methods=['GET', 'POST'])
def register_page():
    form = RegistrationForm(request.form)
    try:

        if request.method == 'POST' and form.validate():
            user_name = form.user_name.data
            email = form.email.data
            password = sha256_crypt.encrypt(str(form.password.data))
            full_name = form.full_name.data
            city = form.zip.data
            address = form.address.data

            if city[3] != ' ':
                city = city[:3] + ' ' + city[3:]
            city_id = get_city(city)
            if city_id is None:
                raise ValueError('Bad zip code!')

            c, conn = connection()
            c.execute('INSERT INTO users(user_name, password, name, email) VALUES (%s, %s, %s, %s)',
                      (user_name, password, full_name, email))

            c.execute('INSERT INTO address(user_id, city_id, part_of_city) VALUES '
                      '((SELECT id FROM users WHERE user_name=%s), %s, %s)',
                      (user_name, city_id, address))
            conn.commit()

            c.close()
            conn.close()
            session['logged-in'] = True
            session['user_name'] = user_name
            session['user_id'] = user_name
            session['admin'] = 0

            return redirect(url_for('index'))
        return render_template("register.html", form=form)
    except ValueError as e:
        flash(f"{e}")
        return render_template("register.html", form=form)
    except IntegrityError:
        flash("Username already used")
        return render_template("register.html", form=form)
    except Exception as e:
        flash(f"{e}")
        print(f"{e}")
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
            return redirect(url_for('index'))

    return admin_control


def get_state():
    c, conn = connection()
    choices = []

    c.execute('SELECT state_id, state_name FROM state')

    for row in c.fetchall():
        choices += [(str(row[0]), str(row[1]))]
    c.close()
    return choices


def get_region():
    c, conn = connection()
    choices = []

    c.execute('SELECT region_id, region_name FROM region')

    for row in c.fetchall():
        choices += [(str(row[0]), str(row[1]))]
    c.close()
    return choices


def get_city(city_zip):
    c, conn = connection()
    c.execute('SELECT id FROM city WHERE psc=%s', [city_zip])
    city_id = c.fetchone()
    c.close()
    return city_id


@app.route("/logout/")
@login_required
def logout():
    session.clear()
    flash("Logged out")
    return redirect(url_for('index'))


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
                session['admin'] = data[5]

                flash("Logged in")
                return redirect(url_for('index'))
            else:
                flash("Invalid username or password")
        return render_template("login.html")

    except TypeError:
        flash("Nic si nezadal")
        return render_template("login.html")
    except Exception as e:
        flash(e)
        return render_template("login.html")


@app.route('/', methods=['GET', 'POST'], defaults={"page": 1})
@app.route('/products/', methods=['GET', 'POST'], defaults={"page": 1})
@app.route('/<int:page>', methods=['GET', 'POST'])
def index(page):
    form = FindName(request.form)
    products = None
    categories = None

    try:
        c, conn = connection()
        categories = get_categories()

        if request.method == 'POST':
            c.execute('SELECT * FROM product WHERE UPPER(product_name) LIKE UPPER(%s)',
                      ['%' + form.find_name.data + '%'])
            products = c.fetchall()
            return render_template("products.html", form=form, page=page, products=products, categories=categories)
        else:
            page = page
            per_page = 20
            start = (page - 1) * per_page
            end = per_page
            c.execute('SELECT * FROM product ORDER BY product_id OFFSET (%s) ROWS FETCH NEXT %s ROWS ONLY',
                      (start, end))
            products = c.fetchall()
            return render_template("products.html", form=form, page=page, products=products, categories=categories)
    except Exception as e:
        flash(e)
        return render_template("products.html", form=form, page=page, products=products, categories=categories)


@app.route('/products/filter/<category_id>')
def products_page_filter(category_id):
    c, conn = connection()
    categories = get_categories()
    c.execute('SELECT * FROM product WHERE cid=%s ORDER  BY product_id', category_id)
    products = c.fetchall()
    return render_template("products.html", products=products, categories=categories)


@app.route('/dashboard/')
@login_required
@admin_required
def dashboard_page():
    c, conn = connection()
    c.execute('SELECT COUNT(order_id), "date", SUM(price), MAX(price) FROM "order" '
              'WHERE "open"=FALSE GROUP BY "date" HAVING SUM(price) > 15000 ORDER BY SUM(price) DESC LIMIT 50')
    stat1 = c.fetchall()
    c.execute('SELECT users.user_name, COUNT("order".order_id), SUM("order".price) FROM "order"'
              'INNER JOIN users ON user_id= users.id '
              'GROUP BY user_id, user_name HAVING SUM(price) > (SELECT AVG(price) FROM "order") '
              'ORDER BY SUM(price) DESC LIMIT 50')

    stat2 = c.fetchall()
    return render_template("dashboard.html", stat1=stat1, stat2=stat2)


@app.route('/dashboard/orders/')
@login_required
@admin_required
def dash_order_page():
    c, conn = connection()
    query_orders = 'SELECT "order".*, users.id, users.user_name FROM "order" ' \
                   'INNER JOIN users ON "order".user_id=users.id ORDER BY "open" DESC'
    c.execute(query_orders)
    order_list = c.fetchall()

    c.execute('SELECT COUNT(order_id) FROM "order"')
    all_orders = c.fetchone()
    c.execute('SELECT COUNT(order_id) FROM "order" WHERE open=TRUE ')
    open_orders = c.fetchone()
    return render_template("dash_orders.html", orders=order_list, open=open_orders, all=all_orders)


@app.route('/dashboard/products/', methods=['GET', 'POST'], defaults={"page": 1})
@app.route('/dashboard/products/page/', methods=['GET', 'POST'], defaults={"page": 1})
@app.route('/dashboard/products/page/<int:page>', methods=['GET', 'POST'])
@login_required
@admin_required
def dash_products_page(page):
    c, conn = connection()
    per_page = 100
    start = (page - 1) * per_page
    end = per_page
    query_orders = 'SELECT "product".*, brand_name, category_name FROM product ' \
                   'INNER JOIN brand ON bid=brand_id ' \
                   'INNER JOIN category ON  cid=category_id ORDER BY product.product_id ' \
                   'OFFSET (%s) ROWS FETCH NEXT %s ROWS ONLY'
    c.execute(query_orders, (start, end))
    products_list = c.fetchall()
    return render_template("dash_products.html", products=products_list, page=page)


@app.route('/dashboard/users/', methods=['GET', 'POST'], defaults={"page": 1})
@app.route('/dashboard/users/page/', methods=['GET', 'POST'], defaults={"page": 1})
@app.route('/dashboard/users/page/<int:page>', methods=['GET', 'POST'])
@login_required
@admin_required
def dash_users_page(page):
    c, conn = connection()
    per_page = 100
    start = (page - 1) * per_page
    end = per_page
    query_orders = 'SELECT users.*, address.part_of_city, city.fullname, city.psc, region.region_name, ' \
                   'state.state_name FROM users, address ' \
                   'INNER JOIN city ON address.city_id=city.id ' \
                   'INNER JOIN region ON city.region_id=region.region_id ' \
                   'INNER JOIN state ON region.state_id=state.state_id ' \
                   'WHERE address.user_id=users.id ORDER BY users.id ' \
                   'OFFSET (%s) ROWS FETCH NEXT %s ROWS ONLY'
    c.execute(query_orders, (start, end))
    users_list = c.fetchall()

    return render_template('dash_users.html', users=users_list, page=page)


@app.route('/dashboard/users/<user_id>/', methods=['GET', 'POST'])
@login_required
@admin_required
def dash_users_page_id(user_id):
    form = DashUserForm(request.form)

    c, conn = connection()

    c.execute('SELECT users.*, address.part_of_city, city.psc, city.fullname, region.region_name, state.state_name '
              'FROM users, address '
              'INNER JOIN city ON address.city_id=city.id '
              'INNER JOIN region ON city.region_id=region.region_id '
              'INNER JOIN state ON region.state_id=state.state_id WHERE users.id=%s AND address.user_id=%s',
              (user_id, user_id))
    user = c.fetchone()

    try:

        if request.method == 'POST' and request.form['buttonpost'] == 'update':
            user_name = form.nick._value()
            email = form.email.data
            password = sha256_crypt.encrypt(str(form.newPass.data))
            full_name = form.full_name.data
            address = form.address.data
            admin = form.admin.data
            city = form.city.data
            if city[3] != ' ':
                city = city[:3] + ' ' + city[3:]
            city_id = get_city(city)
            if city_id is None:
                raise ValueError('Bad zip code!')

            if password == '':
                c.execute('UPDATE address SET city_id=%s, part_of_city=%s WHERE user_id=%s', (city_id, address,
                                                                                              user_id))
                c.execute('UPDATE users SET name=%s, email=%s, permission=%s WHERE user_name=%s',
                          (full_name, email, admin, user_name))
            else:
                c.execute('UPDATE address SET city_id=%s, part_of_city=%s WHERE user_id=%s', (city_id, address,
                                                                                              user_id))
                c.execute('UPDATE users SET password = %s, name=%s, email=%s, permission=%s '
                          'WHERE user_name=%s', (password, full_name, email, admin, user_name))
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
            form.process()
            return render_template("dash_user_update.html", user=user, form=form)
    except ValueError as e:
        flash(e)
        form.process()
        return render_template("dash_user_update.html", user=user, form=form)
    except Exception as e:
        flash(f"{e}")
        print(f"{e}")
        form.process()
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
            price = form.product_price._value()
            product_description = form.product_description.data
            file = request.files['product_image']
            if file is not None:
                c.execute("SELECT nextval('product_product_id_seq')")
                product_id = c.fetchone()
                filename = str(product_id[0]) + '_' + file.filename
                pathname = '/static/images/products/thumbs/' + filename
            else:
                product_id = 0
                pathname = '../default.jpg'
            bid = form.bid.data
            cid = form.cid.data
            c.execute(
                'INSERT INTO product(product_name, product_price, product_description, product_image, bid, cid) '
                'VALUES (%s, %s, %s, %s, %s, %s)',
                (product_name, float(price), product_description, pathname, bid, cid))
            conn.commit()

            flash("Product has been added")
            if file.filename is not '':
                filename = str(product_id[0]) + '_' + file.filename
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                im = Image.open(os.path.join(app.config['UPLOAD_FOLDER'] + filename))
                crop_image(im, filename)

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
                filename = str(product[0]) + '_' + file.filename
                pathname = '/static/images/products/thumbs/' + filename

                c.execute('UPDATE product SET product_name = %s, product_price=%s, product_description=%s, '
                          'product_image=%s, bid=%s, cid=%s '
                          'WHERE product_id=%s', (product_name, float(price), product_description, pathname, bid, cid,
                                                  product[0]))

                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                im = Image.open(os.path.join(app.config['UPLOAD_FOLDER'] + filename))
                crop_image(im, filename)
            else:

                c.execute('UPDATE product SET product_name = %s, product_price=%s, product_description=%s, '
                          'bid=%s, cid=%s '
                          'WHERE product_id=%s',
                          (product_name, float(price), product_description, bid, cid, product[0]))

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

    orders = find_order(c)

    if orders is not None:
        order_id = orders[0]
        query_orders = ('SELECT order_item.*, product.product_name, product.product_price, product.product_image, '
                        'category.category_name FROM order_item '
                        'INNER JOIN product ON order_item.product_id=product.product_id '
                        'INNER JOIN category ON product.cid=category.category_id '
                        'WHERE order_id = %s ORDER BY product.product_id' % order_id)
        c.execute(query_orders)
        product_list = c.fetchall()
        return render_template("cart.html", products=product_list, order_info=orders)
    else:
        return render_template("cart.html", products=products, order_info=orders)


def find_order(c):
    c.execute('SELECT * FROM "order" WHERE user_id=%s AND open=True' % session['user_id'])
    orders = c.fetchone()

    return orders


@app.route('/cart/update', methods=['POST'])
@login_required
def cart_update_count():
    c, conn = connection()
    count = request.form['count']
    order_item_id = request.form['order_item_id']
    try:
        if request.method == 'POST':

            if count != '0':
                c.execute('UPDATE order_item SET "count"=%s WHERE order_item_id=%s', (count, order_item_id))
            else:
                c.execute('DELETE FROM order_item WHERE order_item_id=%s', [order_item_id])

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


def find_product(c, product_id, order_id):
    c.execute('SELECT order_id FROM order_item WHERE product_id=%s AND order_id=%s', (product_id, order_id))
    orders = c.fetchone()

    return orders


@app.route('/cart/add', methods=['POST'])
@login_required
def cart_page_add():
    c, conn = connection()

    orders = find_order(c)
    product_id = request.form['product_id']
    try:
        if orders is not None:
            print(f"{find_product(c, product_id, orders[0])}")
            if find_product(c, product_id, orders[0]) is None:
                c.execute('INSERT INTO order_item(product_id, order_id, count) VALUES (%s, %s, %s)',
                          (product_id, orders[0], 1))
            else:
                c.execute('UPDATE order_item SET count=count + 1 WHERE product_id=%s AND order_id=%s',
                          (product_id, orders[0]))

        else:
            c.execute('INSERT INTO "order"(user_id) VALUES (%s)' % session['user_id'])

            orders = find_order(c)
            c.execute('INSERT INTO order_item(product_id, order_id, count) VALUES (%s, %s, %s)',
                      (request.form['product_id'], orders[0], 1))
        conn.commit()
        c.close()
        conn.close()

        flash("Added to cart")
        return redirect(url_for('index'))

    except Exception as e:
        print(f"{e}")
        flash(f"{e}")
        return redirect(url_for('index'))


def crop_image(image, filename):
    width = image.size[0]
    height = image.size[1]
    aspect = width / float(height)

    ideal_width = 300
    ideal_height = 200

    ideal_aspect = ideal_width / float(ideal_height)
    if aspect > ideal_aspect:
        # Then crop the left and right edges:
        new_width = int(ideal_aspect * height)
        offset = (width - new_width) / 2
        resize = (offset, 0, width - offset, height)
    else:
        # ... crop the top and bottom:
        new_height = int(width / ideal_aspect)
        offset = (height - new_height) / 2
        resize = (0, offset, width, height - offset)

    thumb = image.crop(resize).resize((ideal_width, ideal_height), Image.ANTIALIAS)
    thumb.save(os.path.join(app.config['UPLOAD_FOLDER'] + '/thumbs/', filename))


# INSERTING dumb data to database
def do_faker_users():
    faker = Faker('cz_CZ')
    faker = Faker('sk_SK')
    fakerr = Faker('pl_PL')
    c, conn = connection()
    password = sha256_crypt.encrypt('password')

    for i in range(10000):
        try:
            user_name = fakerr.user_name()
            full_name = faker.name()
            city_id = random.randrange(1, 4208)
            address = faker.street_address()

            email = faker.safe_email()

            print(f"{i, user_name, password, full_name, email, user_name, city_id, address}")
            c.execute('INSERT INTO users(user_name, password, name, email) VALUES (%s, %s, %s, %s)',
                      (user_name, password, full_name, email))

            c.execute('INSERT INTO address(user_id, city_id, part_of_city) VALUES '
                      '((SELECT id FROM users WHERE user_name=%s), %s, %s)',
                      (user_name, city_id, address))
            conn.commit()

        except Exception as e:
            conn.rollback()
            print(f"{e}")
    c.close()
    conn.close()


def give_manu(data):
    x = set([])
    for p in data:
        try:
            x.add(p['manufacturer'])
        except:
            continue
    return x


def give_cat(data):
    x = set([])
    for p in data:
        for y in p['category']:
            x.add(y['name'])
    return x


def add_brand(x):
    for manu in x:
        name = manu
        quality = random.randrange(0, 5)
        descr = faker.sentence()
        print(f"{name, quality, descr}")
        try:
            c.execute('INSERT INTO brand(brand_name, quality, description) VALUES (%s, %s, %s)', (name, quality, descr))
            conn.commit()
        except:
            conn.rollback()


def add_cat(x):
    for manu in x:
        name = manu
        descr = faker.sentence()
        print(f"{name, descr}")
        try:
            c.execute('INSERT INTO category(category_name, description) VALUES (%s, %s)', (name, descr))
            conn.commit()
        except:
            conn.rollback()


def insert_products():
    with open('products2.json') as json_file:
        data = json.load(json_file)
        x = give_manu(data)
        y = give_cat(data)
        c, conn = connection()
        faker = Faker('cz_CZ')
        # add_brand(x)
        # add_cat(y)
        for p in data:
            name = p['name']
            price = p['price']
            descr = p['description']
            img = '/static/images/products/default.jpg'
            try:
                brand = p['manufacturer']
            except:
                brand = None

            try:
                category = p['category'][0]['name']
            except:
                category = None

            if brand is not None and category is not None:
                try:
                    query = 'SELECT brand_id FROM brand WHERE brand_name LIKE %s'
                    c.execute(query, [brand])
                    bid = c.fetchone()
                    if bid is None:
                        bid = 3
                    query = 'SELECT category_id FROM category WHERE category_name LIKE %s'
                    c.execute(query, [category])
                    cid = c.fetchone()
                    if cid is None:
                        cid = 4
                    print(f"{name, price, descr, img, bid, cid}")
                    c.execute('INSERT INTO product(product_name, product_price, product_description, product_image, '
                              'bid, cid) VALUES (%s, %s, %s, %s, %s, %s)', (name, price, descr, img, bid, cid))
                    conn.commit()
                except Exception as e:
                    conn.rollback()
                    print(e)


def insert_orders():
    fake = Faker()
    c, conn = connection()
    c.execute('SELECT id FROM users')
    users = c.fetchall()
    c.execute('SELECT product_id, product_price FROM product')
    products = c.fetchall()
    for x in range (50000):
        try:
            user_id = random.choices(users)
            start_date = datetime.date(year=2018, month=1, day=1)
            end_date = datetime.date(year=2020, month=5, day=1)
            date = fake.date_between(start_date=start_date, end_date=end_date)
            date = date.strftime("%Y-%m-%d")
            sumprice = 0
            product_new = []
            user_id = user_id[0][0]
            for x in range(random.randrange(1, 15)):
                product = random.choices(products)
                product_new.append(product)
                sumprice += product[0][1]
            c.execute('INSERT INTO "order"(user_id, "date", price, "open") VALUES (%s, %s, %s ,%s) RETURNING order_id',
                      (user_id, date, sumprice, False))
            order_id = c.fetchone()[0]
            for p in product_new:
                print(p[0][1])
                c.execute('INSERT INTO order_item(product_id, order_id, "count") VALUES (%s, %s, %s)',
                          (p[0][0], order_id, 1))
            conn.commit()
        except Exception as e:
            print(e)
            conn.rollback()


# do_faker_users()
# insert_products()
#insert_orders()

if __name__ == '__main__':
    app.debug = True
    app.run()
