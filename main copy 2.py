# import sqlite3

# db = sqlite3.connect('new-database.db')
# cursor = db.cursor()

# #cursor.execute("CREATE TABLE books (id INTEGER PRIMARY KEY, title varchar(250) NOT NULL UNIQUE, author varchar(250) NOT NULL, rating FLOAT NOT NULL)")
# cursor.execute("INSERT INTO books VALUES(3, 'Harry Potter3', 'J. K. Rowling', '9.3')")
# db.commit()

from flask import Flask
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)

##CREATE DATABASE 
app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:///new-book-collection.db"
#Optional: But it will silence the deprecation warning in the console.
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


##CREATE TABLE
class Book(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(250), unique=True, nullable=False)
    author = db.Column(db.String(250), nullable=False)
    rating = db.Column(db.Float, nullable=False)

    #Optional: this will allow each book object to be identified by its title when printed.
    def __repr__(self):
        return f'{self.title}-{self.author}-{self.rating}'
    
with app.app_context():
    db.create_all()

#CREATE RECORD
with app.app_context():   
    new_book = Book(title="Harry Potter2", author="J. K. Rowling", rating=9.3)
    db.session.add(new_book)
    db.session.commit()

#ALL DB 
with app.app_context():
    all_books = db.session.execute(db.select(Book)).scalars()
    print(all_books)
    book_list = [book for book in all_books]
    print(book_list)
    all_books = db.session.query(Book).all()
    print(all_books)
    all_books = Book.query.all()
    print(all_books)
#PARTICULAR PIECE OF DB
with app.app_context():
    book = db.session.execute(db.select(Book).where(Book.title == "Harry Potter")).scalar()
    print(book)
    book = db.session.query(Book).filter_by(title="Harry Potter").first()
    print(book)
    book = Book.query.filter_by(title="Harry Potter").first()
    print(book)
#UPDATE
with app.app_context():
    book_to_update = db.session.execute(db.select(Book).where(Book.title == "Harry Potter")).scalar()
    book_to_update.title = "Harry Potter and the Chamber of Secrets"
    db.session.commit() 

#UPDATE WITH PRIMARY KEY(BOOK ID)
book_id = 2
with app.app_context():
    book_to_update = db.session.execute(db.select(Book).where(Book.id == book_id)).scalar()
    # or book_to_update = db.session.get(Book, book_id)  
    # Note Book.query.get() is deprecated
    book_to_update.title = "Harry Potter and the Goblet of Fire"
    db.session.commit()

#DELETE A PARTICULAR BY PRIMARY KEY(WE SETTED ID FOR PRIMARY)
book_id = 1
with app.app_context():
    book_to_delete = db.session.execute(db.select(Book).where(Book.id == book_id)).scalar()
    db.session.delete(book_to_delete)
    db.session.commit()