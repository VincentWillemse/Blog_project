from flask import Flask, render_template, redirect, url_for, flash, request, abort, g
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from functools import wraps
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import Table, Column, Integer, ForeignKey
from sqlalchemy.orm import relationship
from sqlalchemy.ext.declarative import declarative_base
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm
from flask_gravatar import Gravatar

app = Flask(__name__)
app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
ckeditor = CKEditor(app)
Bootstrap(app)
login_manager = LoginManager()
login_manager.init_app(app)
Base = declarative_base()


##CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

##CONFIGURE TABLES
class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(250), nullable=False)
    email = db.Column(db.String(250), unique=True, nullable=False)
    password = db.Column(db.String(250), nullable=False)
    posts = relationship("BlogPost", back_populates="author")
    comments = relationship("PostComment", back_populates="comment_author")

class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    author = db.Column(db.String(250), nullable=False)
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    author_id = Column(Integer, ForeignKey('users.id'))
    author = relationship("User", lazy='subquery', back_populates="posts")
    comments = relationship("PostComment", back_populates="blog_post")

class PostComment(db.Model):
    __tablename__ = "post_comments"
    id = db.Column(db.Integer, primary_key=True)
    comment = db.Column(db.Text, nullable=False)
    blog_post_id = Column(Integer, ForeignKey('blog_posts.id'))
    blog_post = relationship("BlogPost", lazy='subquery', back_populates="comments")
    author_id = Column(Integer, ForeignKey('users.id'))
    comment_author = relationship("User", lazy='subquery', back_populates="comments")

def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user is None:
            abort(404)
        elif current_user.id != 1:
            abort(403)
        return f(*args, **kwargs)
    return decorated_function

@login_manager.user_loader
def load_user(user_id):
    with app.app_context():
        return User.query.get(user_id)

@app.route('/')
def get_all_posts():
    #print(current_user.name)
    posts = BlogPost.query.all()
    return render_template("index.html", all_posts=posts)


@app.route('/register', methods=['POST','GET'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        with app.app_context():
            user_email = form.email.data
            check_email = User.query.filter_by(email = user_email).first()
            if check_email:
                flash("Email already used")
                return redirect(url_for("login"))
            else:
                users = User.query.all()
                print(users)
                id = len(users)+1
                hashed_password = generate_password_hash(form.password.data, method="pbkdf2:sha256", salt_length=8)
                new_user = User(
                    id = id,
                    name=form.name.data,
                    email=form.email.data,
                    password=hashed_password,
                )
                db.session.add(new_user)
                db.session.commit()
                login_user(new_user)
                return redirect(url_for("get_all_posts"))
    else:
        return render_template("register.html", form=form)

@app.route('/login', methods=['POST','GET'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        with app.app_context():
            user_email = form.email.data
            user_password = form.password.data
            user = User.query.filter_by(email = user_email).first()
            if not user or not check_password_hash(user.password, user_password):
                flash("Wrong email or password")
                return render_template("login.html", form=form)
            else:
                login_user(user)
                return redirect(url_for("get_all_posts"))
    else:
        return render_template("login.html", form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))

@app.route("/post/<int:post_id>", methods=['POST','GET'])
def show_post(post_id):
    with app.app_context():
        print(db.session)
        requested_post = BlogPost.query.get(post_id)
        comments = PostComment.query.filter_by(blog_post=requested_post)
        comment_form = CommentForm()
        if comment_form.validate_on_submit():
            new_comment = PostComment(
                comment=comment_form.comment.data,
                blog_post=requested_post,
                comment_author=current_user,
            )
            print(db.session)
            db.session.add(new_comment)
            print(new_comment)
            db.session.commit()
            return redirect(url_for("get_all_posts"))

    return render_template("post.html", post=requested_post, all_comments =comments, form=comment_form)


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


@app.route("/new-post", methods=['POST','GET'])
@admin_only
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        with app.app_context():
            new_post = BlogPost(
                title=form.title.data,
                subtitle=form.subtitle.data,
                body=form.body.data,
                img_url=form.img_url.data,
                author=current_user,
                date=date.today().strftime("%B %d, %Y")
            )
            db.session.add(new_post)
            db.session.commit()
            return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form)


@app.route("/edit-post/<int:post_id>")
@admin_only
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.author = edit_form.author.data
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form)


@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000)
