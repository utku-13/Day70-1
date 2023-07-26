from flask import Flask, render_template, redirect, url_for, flash, abort
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm, CreateRegisterForm, CreateLoginForm, CreateCommentForm
from flask_gravatar import Gravatar
from functools import wraps
#from sqlalchemy import ForeignKey

app = Flask(__name__)
app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
ckeditor = CKEditor(app)
Bootstrap(app)

##CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

gravatar = Gravatar(app,
                    size=100,
                    rating='g',
                    default='retro',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None)

##CONFIGURE TABLES

class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    author = db.Column(db.String(250), nullable=False)
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    #####
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))

    user = db.relationship('Users',back_populates='blogs')
    ###
    comment = db.relationship('Comments', back_populates='blogs')

class Users(db.Model, UserMixin):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(250), nullable=False)
    email = db.Column(db.String(250), nullable=False)
    password = db.Column(db.String(250), nullable=False)
    ###
    blogs = db.relationship('BlogPost',back_populates='user')
    ###
    comment = db.relationship('Comments', back_populates='user')
    ###
class Comments(db.Model):
    __tablename__= 'comments'
    id = db.Column(db.Integer,primary_key=True)
    text = db.Column(db.String(500), nullable=False)
    ###
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))

    user = db.relationship('Users', back_populates='comment')
    ###
    blog_id = db.Column(db.Integer, db.ForeignKey('blog_posts.id'))
    
    blogs = db.relationship('BlogPost', back_populates='comment')

with app.app_context():
    db.create_all()

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

@login_manager.user_loader
def load_user(user_id):
    return Users.query.get(int(user_id))

@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()
    return render_template("index.html", all_posts=posts)


@app.route('/register',methods=["GET","POST"])
def register():
    register_form = CreateRegisterForm()
    if register_form.validate_on_submit():
        hash_and_salted_password = generate_password_hash(
                register_form.password.data,
                method='pbkdf2:sha256',
                salt_length=8)

        new_user = Users(
            name = register_form.name.data,
            email = register_form.email.data,
            password = hash_and_salted_password
        )
        db.session.add(new_user)
        db.session.commit()
        return  redirect(url_for('get_all_posts'))
    else:
        flash('this email already registered in','error')
    return render_template("register.html",form=register_form)


@app.route('/login',methods=['GET','POST'])
def login():
    login_form = CreateLoginForm()
    if login_form.validate_on_submit():
        user = db.session.query(Users).filter_by(email=login_form.email.data).first()
        if user: 
            print(user.password)
            if check_password_hash(user.password,login_form.password.data):
                login_user(user)
                return redirect(url_for('get_all_posts',))
            else:
                flash('Bro check your password','error')
                return redirect(url_for('login'))
        else:
            flash('We could not find the user','error')
            return redirect(url_for('login'))

    return render_template("login.html",form = login_form)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>",methods=['GET','POST'])
@login_required
def show_post(post_id):
    form = CreateCommentForm()
    requested_post = BlogPost.query.get(post_id)
    users = db.session.query(Users).all()
    comments = db.session.query(Comments).filter_by(blog_id=post_id).all()
    if form.validate_on_submit():
        comment = Comments(
            text=form.comment.data,
            user=current_user,
            blogs=requested_post
            )
        db.session.add(comment)
        db.session.commit()
        return redirect(url_for('show_post',post_id=post_id))
    # with app.app_context():
    #     comments = db.session.query(Comments).filter_by()
    return render_template("post.html", post=requested_post, form=form, comments=comments,users=users)

@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")

def only_admin(f):
    @wraps(f)
    def decorated_function(*args,**kwargs):
        print(current_user.id)
        if current_user.id != 1:
            return abort(403)
        return f(*args,**kwargs)
    return decorated_function

@app.route("/new-post",methods=["GET",'POST'])
@only_admin
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=current_user.name,
            date=date.today().strftime("%B %d, %Y"),
            user=current_user
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form)


@app.route("/edit-post/<int:post_id>",methods=['GET','POST'])
@only_admin
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
        post.author = current_user.name
        post.body = edit_form.body.data
        post.user=current_user
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form)


@app.route("/delete/<int:post_id>")
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))



if __name__ == "__main__":
    app.run(debug=True)