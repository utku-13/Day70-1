from flask import Flask, render_template, request, url_for, redirect, flash, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user

app = Flask(__name__)

app.config['SECRET_KEY'] = 'any-secret-key-you-choose'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

##CREATE TABLE IN DB
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(1000))
#Line below only required once, when creating DB. 
# db.create_all()


login_manager = LoginManager ()
login_manager.init_app(app)
login_manager.login_view = "login"

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def home():
    return render_template("index.html")


@app.route('/register',methods=['GET','POST'])
def register():
    if request.method == 'POST' :
        with app.app_context():
            user = db.session.query(User).filter_by(email= request.form.get('email')).first()
        if not user:
            hash_and_salted_password = generate_password_hash(
                request.form.get('password'),
                method='pbkdf2:sha256',
                salt_length=8
            )
            new_user = User(
                email=request.form.get('email'),
                name=request.form.get('name'),
                password=hash_and_salted_password,
            )                   
            
            db.session.add(new_user)
            db.session.commit()
        else:
            flash('This email already Logged In','error')
        return redirect(url_for("secrets",name=request.form.get('name'),logged_in=current_user.is_authenticated))
    return render_template("register.html")


@app.route('/login',methods=['GET','POST'])
def login():
    if request.method == 'POST':
        print('yes')
        name=request.form.get('email')
        print(name)
        user = db.session.query(User).filter_by(email=request.form.get('email')).first() 
        if user:
            #if True:
            if check_password_hash(user.password, request.form.get('password')):
                login_user(user)
                print(current_user.is_authenticated)
                return redirect(url_for('secrets',name=name,logged_in=current_user.is_authenticated))
            else:
                flash('Invalid password.', 'error')
        else:
            flash('User not Found', 'error')
    return render_template("login.html")


@app.route('/secrets/<name>/<logged_in>',methods=['GET','POST'])
@login_required
#bu secretsa girmek icin kural koydu!
def secrets(name,logged_in):
    return render_template("secrets.html",name=name,logged_in=logged_in)

    
    


@app.route('/logout',methods=['GET','POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


@app.route('/download')
def download():
    return send_from_directory(directory='static/files', path="cheat_sheet.pdf", as_attachment=True)


if __name__ == "__main__":
    app.run(debug=True)
