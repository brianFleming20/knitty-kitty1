from flask import Flask, render_template, redirect, url_for, flash, abort, request
from flask_wtf import FlaskForm
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor, CKEditorField
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from wtforms import StringField, SubmitField
from wtforms.validators import DataRequired, URL
from functools import wraps
from forms import CreatePostForm
from flask_mail import Mail, Message

app = Flask(__name__)
app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
ckeditor = CKEditor(app)
Bootstrap(app)

##CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///kitty-sales.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

app.config['MAIL_SERVER']='smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USERNAME'] = 'knittykittyco@gmail.com'
app.config['MAIL_PASSWORD'] = '*****'
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True
# create dotenv for email and password

mail = Mail(app)

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
    comment = relationship("Comments", back_populates="parent_post")
# db.create_all()


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


class boughtBy(db.Model):
    __tablename__ = "sales"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("Users.id"))
    item = db.Column(db.Integer, db.ForeignKey("kitty_posts.id"))
    date = db.Column(db.String(100), nullable=False)


class basket(db.Model):
    __tablename__ = "basket"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("Users.id"))
    item1 = db.Column(db.Integer, db.ForeignKey("item.id"))
    items = db.Column(db.JSON)


class orderItem(db.Model):
    __tablename__ = "item"
    id = db.Column(db.Integer, primary_key=True)
    item = db.Column(db.Integer, db.ForeignKey("kitty_posts.id"))
    quantity = db.Column(db.Integer, nullable=False)


db.create_all()


# Create form for registration of new user
class RegisterForm(FlaskForm):
    name = StringField("Name", validators=[DataRequired()])
    email = StringField("Email", validators=[DataRequired()])
    password = StringField("Password", validators=[DataRequired()])
    submit = SubmitField("Sign me up!")


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
    submit = SubmitField("Make new post")


class CommentForm(FlaskForm):
    comment_text = CKEditorField("Comment", validators=[DataRequired()])
    submit = SubmitField("Submit Comment")


@app.route('/', methods=["POST", "GET"])
def get_all_posts():
    posts = KittyPost.query.all()

    # data = request.form.get('ckeditor')
    return render_template("index.html", all_posts=posts, current_user=current_user)


@app.route('/register', methods=["POST", "GET"])
def register():
    form = RegisterForm()
    user = User.query.filter_by(email=form.email.data).first()

    if form.validate_on_submit():
        if user:
            flash("You've already signed up with that email, log in instead!")
            return redirect(url_for('login'))
        password = form.password.data
        encrypted = generate_password_hash(password, method='pbkdf2:sha256', salt_length=8)
        new_user = User(
            name=form.name.data,
            email=form.email.data,
            password=encrypted,
        )
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
        return redirect(url_for("get_all_posts"))

    return render_template("register.html", form=form, current_user=current_user)


@app.route('/login', methods=["POST", "GET"])
def login():
    form = UserLogin()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data
        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for("get_all_posts"))
        else:
            flash("Your email does not exist, please register.")
            return redirect(url_for("register"))
    return render_template("login.html", form=form, current_user=current_user)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>", methods=["POST", "GET"])
def show_post(post_id):
    comment_form = CommentForm()
    requested_post = KittyPost.query.get(post_id)
    # comments = requested_post.comment
    if comment_form.validate_on_submit():
        if not current_user.is_authenticated:
            flash("You need to login or register to comment.")
            return redirect(url_for("login"))
        new_comment = Comments(
            text=comment_form.comment_text.data,
            comment_author=current_user,
            parent_post=requested_post
        )
        db.session.add(new_comment)
        db.session.commit()
        return redirect(url_for("show_post", post_id=post_id))
    return render_template("post.html", post=requested_post, current_user=current_user, form=comment_form)


@app.route("/about")
def about():
    return render_template("about.html", current_user=current_user)


@app.route("/contact")
def contact():
    text = "Knitty"
    return render_template("contact.html", current_user=current_user)


@app.route("/new-post", methods=["POST", "GET"])
@admin_only
def add_new_post():
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
    return render_template("make-post.html", form=form, current_user=current_user)


@app.route("/edit-post/<int:post_id>", methods=["POST", "GET"])
@admin_only
def edit_post(post_id):
    post = KittyPost.query.get(post_id)
    edit_form = CreatePost(
        title=post.title,
        description=post.description,
        img_url=post.img_url,
        author=post.author.name,
        author_id=current_user.id,
        price=post.price,
        make_days=post.make_day,
        stock_quantity=post.stock_quantity,
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

    return render_template("make-post.html", form=edit_form, current_user=current_user, is_edit=True)


@app.route("/basket/<int:post_id>", methods=["POST", "GET"])
def basket(post_id):
    requested_post = KittyPost.query.get(post_id)
    user_basket.append(requested_post)
    print(user_basket)

    item = {
        "basket_item": requested_post.id
    }

    return render_template("basket.html", current_user=current_user, post=requested_post)


@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    post_to_delete = KittyPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


if __name__ == "__main__":
    app.run(debug=True)
