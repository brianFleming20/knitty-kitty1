from flask import Flask, render_template, redirect, url_for, flash, abort
from flask_wtf import FlaskForm
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor, CKEditorField
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, current_user, logout_user
from wtforms import StringField, SubmitField, TextField, validators
from wtforms.validators import DataRequired
from functools import wraps
import os
from cryptography.fernet import Fernet
import smtplib
from email.message import EmailMessage
from dotenv import load_dotenv, find_dotenv
load_dotenv(find_dotenv())


app = Flask(__name__)
app.config['SECRET_KEY'] = '8BYkEfBA6O6donbWlSihBXox7C0sKR6z'
ckeditor = CKEditor(app)
Bootstrap(app)

##CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///kitty-sales.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

load_dotenv()
private = os.getenv("PASSWORD")
f = Fernet(private)
MAIL_USERNAME = os.environ.get('USER')
MAIL_PASSWORD = os.environ.get('APP-PASS')
KITTY_EMAIL = os.environ.get("EMAIL")
SECRET_KEY = os.environ.get("PASSWORD")
login_manager = LoginManager()
login_manager.init_app(app)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)


def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        #If id is not 1 then return abort with 403 error
        if current_user.id != 1:
            return abort(403)
        if current_user.is_anonymous:
            return abort(403)
        #Otherwise continue with the route function
        return f(*args, **kwargs)
    return decorated_function


user_basket = []

##CONFIGURE TABLES


class KittyPost(db.Model):
    __tablename__ = "kitty_posts"
    id = db.Column(db.Integer, primary_key=True)
    # Foreign Key to link to the user's post
    author_id = db.Column(db.Integer, db.ForeignKey("Users.id"))
    # link the author to the user's post
    author = relationship("User", back_populates="posts")
    title = db.Column(db.String(250), unique=True, nullable=False)
    description = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    price = db.Column(db.String(100), nullable=False)
    stock_quantity = db.Column(db.Integer, nullable=False)
    make_days = db.Column(db.String(50), nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    col_size = db.Column(db.String(250))
    comment = relationship("Comments", back_populates="parent_post")


# User form data
class User(UserMixin, db.Model):
    __tablename__ = "Users"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(250), nullable=False)
    password = db.Column(db.String(250), nullable=False)
    email = db.Column(db.String(250), unique=True, nullable=False)
    posts = relationship("KittyPost", back_populates="author")
    comment = relationship("Comments", back_populates="comment_author")


class Comments(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.Text, nullable=False)
    author_id = db.Column(db.Integer, db.ForeignKey("Users.id"))
    post_id = db.Column(db.Integer, db.ForeignKey("kitty_posts.id"))
    comment_author = relationship("User", back_populates="comment")
    parent_post = relationship("KittyPost", back_populates="comment")


class Address(db.Model):
    __tablename__ = "Address"
    id = db.Column(db.Integer, primary_key=True)
    address1 = db.Column(db.String(100), nullable=False)
    address2 = db.Column(db.String(100), nullable=False)
    address3 = db.Column(db.String(100), nullable=False)
    post_code = db.Column(db.String(50), nullable=False)
    country = db.Column(db.String(50), nullable=False)
    user = db.Column(db.Integer, db.ForeignKey("Users.id"))


class OrderItem(db.Model):
    __tablename__ = "item"
    id = db.Column(db.Integer, primary_key=True)
    item = db.Column(db.Integer, db.ForeignKey("kitty_posts.id"))
    email = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(100), nullable=False)
    total = db.Column(db.String(100), nullable=False)
    custom = db.Column(db.String(250))
    made = db.Column(db.Integer)
    sent = db.Column(db.Integer)
    paid = db.Column(db.Integer)


db.create_all()


# Create form for registration of new user
class RegisterForm(FlaskForm):
    name = StringField("Name", validators=[DataRequired()])
    email = StringField("Email", validators=[DataRequired()])
    password = StringField("Password", validators=[DataRequired()])
    submit = SubmitField("Start Ordering!")


class UserLogin(FlaskForm):
    email = StringField("Email", validators=[DataRequired()])
    password = StringField("Password", validators=[DataRequired()])
    submit = SubmitField("Log me in!")


class CreatePost(FlaskForm):
    title = StringField("Title", validators=[DataRequired()])
    description = StringField("Description", validators=[DataRequired()])
    img_url = StringField("Image URL", validators=[DataRequired()])
    author = StringField("Author", validators=[DataRequired()])
    price = StringField("Price", validators=[DataRequired()])
    stock = StringField("Stock Quantity", validators=[DataRequired()])
    make_day = StringField("Days to make", validators=[DataRequired()])
    body = CKEditorField("Item Content", validators=[DataRequired()])
    submit = SubmitField("List Item")


class CommentForm(FlaskForm):
    comment_text = CKEditorField("Comment", validators=[DataRequired()])
    submit = SubmitField("Submit Comment")


class AddAddress(FlaskForm):
    street = StringField("Street", validators=[DataRequired()])
    street2 = StringField("Street 2")
    town = StringField("Town", validators=[DataRequired()])
    county = StringField("County", validators=[DataRequired()])
    postcode = StringField("Post / Zip code", validators=[DataRequired()])
    country = StringField("Country", validators=[DataRequired()], default="UK")
    submit = SubmitField("Enter Address")


class ContactForm(FlaskForm):
    name = StringField("Name", validators=[DataRequired()])
    email = StringField("Email", validators=[DataRequired()])
    subject = TextField("Subject", [validators.DataRequired('Please enter a Subject !')])
    body = CKEditorField("Message Content", validators=[DataRequired()])
    submit = SubmitField("Submit Request")


class Customise(FlaskForm):
    custom = StringField("Custom element")
    submit = SubmitField("Submit request")


def send_mail(subject, body, to):
    msg = EmailMessage()
    msg.set_content(body)
    msg['subject'] = subject
    msg['to'] = to
    msg['cc'] = KITTY_EMAIL
    user = MAIL_USERNAME
    msg['from'] = user
    password = MAIL_PASSWORD
    server = smtplib.SMTP('smtp.gmail.com', 587)
    server.starttls()
    server.login(user, password)
    server.send_message(msg) # <- UPDATED
    server.quit()
    return True


@app.route('/', methods=["POST", "GET"])
def get_all_posts():
    posts = KittyPost.query.all()
    items = len(user_basket)
    return render_template("index.html", all_posts=posts, current_user=current_user, cart=items)


@app.route('/register', methods=["POST", "GET"])
def register():
    items = len(user_basket)
    form = RegisterForm()
    user = User.query.filter_by(email=form.email.data).first()

    if form.validate_on_submit():
        if user:
            flash("You've already signed up with that email, log in instead!")
            return redirect(url_for('login'))
        encrypted = generate_password_hash(form.password.data, method='pbkdf2:sha256', salt_length=8)
        new_user = User(
            name=form.name.data,
            email=form.email.data,
            password=encrypted,
        )
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
        return redirect(url_for("get_all_posts"))

    return render_template("register.html", form=form, current_user=current_user, cart=items)


@app.route('/login', methods=["POST", "GET"])
def login():
    items = len(user_basket)
    form = UserLogin()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and check_password_hash(user.password, form.password.data):
            login_user(user)
            return redirect(url_for("get_all_posts"))
        else:
            flash("Your email does not exist, please create an order.")
            return redirect(url_for("register"))
    return render_template("login.html", form=form, current_user=current_user, cart=items)


@app.route('/logout')
def logout():
    if current_user.id > 1:
        delete_user = User.query.filter_by(id=current_user.id).one()
        db.session.delete(delete_user)
        Address.query.filter_by(user=current_user.id).delete()
        db.session.commit()
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>", methods=["POST", "GET"])
def show_post(post_id):
    items = len(user_basket)
    # comment_form = CommentForm()
    requested_post = KittyPost.query.get(post_id)
    custom_form = Customise()
    if custom_form.validate_on_submit():
        if not current_user.is_authenticated:
            flash("You need to create an order.")
            return redirect(url_for("login"))
        requested_post.col_size = custom_form.custom.data
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("post.html", post=requested_post, current_user=current_user, form=custom_form, cart=items)


@app.route("/about")
def about():
    items = len(user_basket)
    return render_template("about.html", current_user=current_user, cart=items)


@app.route("/contact", methods=["POST", "GET"])
def contact():
    items = len(user_basket)
    form = ContactForm()
    filepath = "templates/request.txt"
    if form.validate_on_submit():
        name = form.name.data
        send_email = form.email.data
        subject = form.subject.data
        message = form.body.data
        with open(filepath) as letter_file:
            contents = letter_file.read()
            new_contents = contents.replace(
                "[NAME]", name).replace("[subject]", subject).replace(
                "[message]", message).replace("[email]", send_email)

        result = send_mail(subject, new_contents, send_email)
        if result:
            return redirect(url_for('success'))
        else:
            flash("Please try again, check the spelling.")

    return render_template("contact.html", current_user=current_user, form=form, cart=items)


@app.route("/new-post", methods=["POST", "GET"])
@admin_only
def add_new_post():
    items = len(user_basket)
    form = CreatePost()
    if form.validate_on_submit():
        new_post = KittyPost(
            title=form.title.data,
            description=form.description.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=current_user,
            author_id=current_user.id,
            price=form.price.data,
            make_days=form.make_day.data,
            stock_quantity=form.stock.data,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form, current_user=current_user, cart=items)


@app.route("/edit-post/<int:post_id>", methods=["POST", "GET"])
@admin_only
def edit_post(post_id):
    items = len(user_basket)
    post = KittyPost.query.get(post_id)
    edit_form = CreatePost(
        title=post.title,
        description=post.description,
        img_url=post.img_url,
        author=post.author.name,
        author_id=current_user.id,
        price=post.price,
        make_day=post.make_days,
        stock=post.stock_quantity,
        body=post.body
    )

    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.description = edit_form.description.data
        post.img_url = edit_form.img_url.data
        post.author = current_user
        post.author_id = current_user.id
        post.price = edit_form.price
        post.stock_quantity = edit_form.stock
        post.make_day = edit_form.make_day
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form, current_user=current_user, is_edit=True, cart=items)


@app.route("/stock")
@admin_only
def stock_n_orders():
    items = len(user_basket)
    posts = KittyPost.query.all()
    orders = OrderItem.query.all()

    db.session.commit()

    return render_template("stock.html", items=posts, orders=orders, cart=items)


@app.route("/success")
def success():
    global user_basket
    for item in user_basket:
        each = item.id
        each_item = KittyPost.query.filter_by(id=each).first()
        each_item.col_size = None

        db.session.commit()
    user_basket = []
    return render_template("success.html", cart=0)


@app.route("/delete-row/<int:row>", methods=["POST", "GET"])
@admin_only
def delete_row(row):
    OrderItem.query.filter_by(id=row).delete()
    db.session.commit()
    return redirect(url_for('stock_n_orders'))


@app.route("/email-order")
def email():
    items = len(user_basket)
    filepath = "templates/order.txt"
    auser = User.query.filter_by(id=current_user.id).first()
    address = Address.query.filter_by(user=current_user.id).first()
    name = auser.name
    postandpack = "£3.50"
    subject = "New Order."
    ordered_items = []
    addr1 = f.decrypt(address.address1).decode()
    addr2 = f.decrypt(address.address1).decode()
    addr3 = f.decrypt(address.address3).decode()
    post_code = f.decrypt(address.post_code).decode()
    country = f.decrypt(address.country).decode()
    user_email = current_user.email
    cost = [float(item.price[1:]) for item in user_basket]
    total = format(sum(cost) + 3.5, ".2f")
    for item in user_basket:
        orders = OrderItem(
            item=item.id,
            email=user_email,
            date=date.today().strftime("%B %d, %Y"),
            total=item.price,
            custom=item.col_size
        )
        ordered_items.append(f"-> {item.title}")
        ordered_items.append(" - ")
        ordered_items.append(item.price)
        ordered_items.append(" : make time ")
        ordered_items.append(f"{item.make_days} days.")
        ordered_items.append(f" - {item.col_size}")
        ordered_items.append("\n")
        db.session.add(orders)
    db.session.commit()
    orders = ''.join(ordered_items)
    with open(filepath) as letter_file:
        contents = letter_file.read()
        new_contents = contents.replace(
            "[NAME]", name).replace("[subject]", subject).replace(
            "[on]", date.today().strftime("%B %d, %Y")).replace("[email]", user_email).replace(
            "[items]", orders).replace("[address1]", addr1).replace("[address2]", addr2).replace(
            "[address3]", addr3).replace("[post]", post_code).replace("[country]", country).replace(
            "[pandp]", postandpack)

    send_mail(subject, new_contents, user_email)

    return render_template("email-order.html", user=name, email=auser, basket=user_basket, pandp=postandpack, total=total, cart=items)


@app.route("/address", methods=["POST", "GET"])
def address():
    items = len(user_basket)
    name = current_user.name
    form = AddAddress()
    if form.validate_on_submit():
        new_address = Address(
            address1=f.encrypt(form.street.data.encode()),
            address2=f.encrypt(form.town.data.encode()),
            address3=f.encrypt(form.county.data.encode()),
            post_code=f.encrypt(form.postcode.data.encode()),
            country=f.encrypt(form.country.data.encode()),
            user=current_user.id
        )
        db.session.add(new_address)
        db.session.commit()
        return redirect(url_for('basket', post_id=0))
    return render_template("address.html", form=form, name=name, cart=items)


@app.route("/basket/<int:post_id>/", methods=["POST", "GET"])
def basket(post_id):
    btn = 0
    postandpack = "£3.50"
    address = ["No Address"]
    if not current_user.is_authenticated:
        flash("You need to start an order.")
        return redirect(url_for("register"))
    else:
        if Address.query.filter_by(user=current_user.id).first():
            user_address = Address.query.filter_by(user=current_user.id).first()
            add1 = f.decrypt(user_address.address1).decode()
            add2 = f.decrypt(user_address.address2).decode()
            add3 = f.decrypt(user_address.address3).decode()
            pcode = f.decrypt(user_address.post_code).decode()
            country = f.decrypt(user_address.country).decode()
            address = [add1, add2, add3, pcode, country]
            btn = 1
        if post_id > 0:
            requested_post = KittyPost.query.get(post_id)
            user_basket.insert(0, requested_post)
            get_item = KittyPost.query.filter_by(id=post_id).first()
            stock = get_item.stock_quantity - 1
            get_item.stock_quantity = stock
            db.session.commit()

        items = len(user_basket)
        cost = [float(item.price[1:]) for item in user_basket]
        total = format (sum(cost) + 3.5, ".2f")
    return render_template("basket.html", current_user=current_user, posts=user_basket, pandp=postandpack, total=total, address=address, add_btn=btn, cart=items)


@app.route("/remove")
def remove():
    index = user_basket[0]
    get_item = KittyPost.query.filter_by(id=index.id).first()
    stock = get_item.stock_quantity
    get_item.stock_quantity = stock + 1
    db.session.commit()
    del user_basket[0]
    return redirect(url_for("basket", post_id=0))


@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    post_to_delete = KittyPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


if __name__ == "__main__":
    app.run(host='127.0.0.1', port=5000)
