#import necessaary modules 
from flask import Flask, render_template, request, redirect, session, url_for # flaskmodule for web structure 
from werkzeug.security import generate_password_hash, check_password_hash # werkzeung module for password hashing 
from cryptography.fernet import Fernet # cryptography module for encryption and decryption of passwords 
import sqlite3 # sqlite3 for database managemnet 
import os # os for file management

print("DB Path:", os.path.abspath("database.db")) # print the path for database file 


app = Flask(__name__) # creating flask app application 
app.secret_key = os.urandom(24) # setting a secret key for session management 

def init_db(): # function to initilize the dtabase 
     
       
    with sqlite3.connect("database.db") as conn: # connects to the database file 
        c = conn.cursor() # create a cursor object to excute SQL commands 
       # create users and information table 
        c.execute('''CREATE TABLE IF NOT EXISTS users ( 
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        username TEXT UNIQUE NOT NULL,
                        password TEXT NOT NULL,
                        key TEXT NOT NULL)''')
        c.execute('''CREATE TABLE IF NOT EXISTS information (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        user_id INTEGER NOT NULL,
                        site TEXT,
                        site_username TEXT,
                        site_password BLOB,
                        FOREIGN KEY (user_id) REFERENCES users (id))''')
        conn.commit() # commit the changes to the database 




@app.route('/') # route for the home page 
def index(): # function for the home page to check if user is logged in or not 
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('index.html') 

@app.route('/register', methods=['GET', 'POST']) # route for the registration page 
def register(): # function for registration of new users 
    if request.method == 'POST': # checks if reqquest method is POST
        username = request.form['username'] # get the usersname from the form 
        password = request.form['password'] # get the password from the form 
        hashed_password = generate_password_hash(password) # hash the password using werkzeug's generate_password_hash function 
        encryption_key = Fernet.generate_key().decode('utf-8') # generate a new encryotion key using cryptography

        with sqlite3.connect("database.db") as conn: # connects to the database file 
            c = conn.cursor() # creates a cursor object to excute SQL commands
            try: # insert the new user into the users table 
                c.execute("INSERT INTO users (username, password, key) VALUES (?, ?, ?)", 
                          (username, hashed_password, encryption_key)) # excute the SQL command to insert a new user
                conn.commit() # commit the changes to the database
                return redirect(url_for("login")) # redirect to the login page after registration was successful
            except sqlite3.IntegrityError: # checks if username already exisits in the database
                return "Username already exists" # reture 'Username already exists' 
    return render_template('register.html') # render the registration template if the request method is GET

@app.route('/login', methods=["GET", "POST"]) # route for the login page 
def login(): # function for user login 
    if request.method == "POST":  # checks if request method is  POST
        username = request.form['username'] # get the username from the form
        password = request.form['password'] # gets the password from the form 

        with sqlite3.connect("database.db") as conn: # connects to the database file 
            c = conn.cursor() # creates a cursor object to excute SQL commands
            c.execute("SELECT id, password FROM users WHERE username = ?", (username,)) # collects the user id and passord from the users table
            user = c.fetchone() # fetches the first row of the result set 
            if user and check_password_hash(user[1], password): # checks if user exists and the password matches the hashed password in the database
                session['user_id'] = user[0] # stores the user id in the session
                print("login successful ,sesssion user_id:", user[0]) # prints a message when login is successful
                return redirect(url_for('dashboard')) # redirect to the dashboard page after successful login

        return "Invalid credentials" # return 'invalid credentials if the username or password is incorrect
    return render_template('login.html') # render the login template if the request method is GET

@app.route('/dashboard') # route for the dashboard page
def dashboard(): # function for the dashboard page to  show users credntials 
    if 'user_id' not in session: # checks if user is logged in or not 
        return redirect(url_for('login')) # redirect to the login page if user is not logged in
    
    user_id = session['user_id'] # gets the users id for the sesssion
    with sqlite3.connect("database.db") as conn: # conncects to the database file 
        c = conn.cursor() # creates a cursor object to excute SQL commands 
        c.execute("SELECT site, site_username, site_password FROM information WHERE user_id = ?", (user_id,)) #collects the site credentials from the information table for the logged in user
        rows = c.fetchall() # fetches all the rolls from the result set

        c.execute("SELECT key FROM users WHERE id = ?", (user_id,)) # collects the encryption key for the logged in user from theusers table 
        key = c.fetchone()[0] # checks if the key exisits for the user
        fernet = Fernet(key.encode('utf-8')) # creates a Fernet object using the user's encryption key

        credentials = []# list to store decrypted credentials 
        for site, username, encrypted_password in rows: # checks  if the site , username and encrypted passowrd exists in the row 
            decrypted_password = fernet.decrypt(encrypted_password).decode('utf-8') # decrypts the encrypted passowrd using the fernet object
            credentials.append((site, username, decrypted_password)) # adds the site, username and encrypted passowrd to the credential list

    return render_template('dashboard.html', credentials=credentials) # render the dashboard template with the decrypted credentials


@app.route('/add', methods=['GET', 'POST']) # route for adding new credentials 
def add_credentials(): # function for adding new credentials 
    if 'user_id' not in session: # checks if the user is logged in or not
        return redirect(url_for('login')) # rediects login page if user is not logged in

    if request.method == "POST": # checks if the request method is POST
        site = request.form.get('site') # get the site name from the form
        site_username = request.form.get('site_username') # gets the site username from the form
        site_password = request.form.get('site_password') # gets the sites password from the form

        if not site or not site_username or not site_password: # checks if all fields are filled or not
            return "Please fill all fields", 400 # returns " fill all fields " if the field is empty

        with sqlite3.connect("database.db") as conn: # connects to the database file
            # gets the users enctyption key
            c = conn.cursor() # creates a cursor object to excute SQL commands
            c.execute("SELECT key FROM users WHERE id = ?", (session['user_id'],)) # collects the encryption key for the logged in user
            key = c.fetchone()[0] # gets the first row of the result that contains the encryption key
            fernet = Fernet(key.encode('utf-8')) # creates a  fernet object using the users encryption key
            encrypted_password = fernet.encrypt(site_password.encode('utf-8')) # encrypts the sites passowrd using the fernet object
            # Insert the new credential into the information table
            c.execute(""" 
                INSERT INTO information (user_id, site, site_username, site_password)
                VALUES (?, ?, ?, ?)
            """, (session['user_id'], site, site_username, encrypted_password))
            conn.commit() # commits the changes to the database

        return redirect(url_for("dashboard")) # redirect to the dashboard page after adding new credentials

    return render_template('add_credential.html') # render the add credential template if the request method is get


@app.route('/view') # route for viewing stored credentials 
def view_credentials(): # function for viewing stored credentials
    if 'user_id' not in session: # checks if the user is logged in or not 
        return redirect(url_for('login')) # rediect to the login page if user is not logged in

    user_id = session['user_id'] # gets the user id from the session
    with sqlite3.connect("database.db") as conn: # connects to the database file
        c = conn.cursor() # creates a cursor object to excute SQL commands

        # gets users encrption key
        c.execute("SELECT key FROM users WHERE id = ?", (user_id,)) # collects the encryption key for the logged in user
        key_row = c.fetchone() # fetches the first row of the reult 
        if not key_row: # checks if the key row is empty
            return "User key not found", 404 # return 'user key not found' if the key row is empty
        fernet = Fernet(key_row[0].encode()) # creates a fernet object using the users encrtyption key

        # gets stored credentials from the logged in user
       
        c.execute("SELECT site, site_username, site_password FROM information WHERE user_id = ?", (user_id,))
        rows = c.fetchall()


        print("Raw encrypted credentials:", rows) # debugging statement to print raw encrypted credentials

        # decrypt credentials
        data = [(site, fernet.decrypt(pw).decode()) for site, pw in rows]

        print("Decrypted credentials:", data) # debugging statement to print decrypted credentials

    return render_template("view_credentials.html", data=data) # render the view credntials templates with the decrypted credentals


@app.route('/logout') # route for logged out page
def logout(): # function for logging out the user
    session.pop('user_id', None) # removes the user id from the session
    return redirect(url_for('index')) # redirect to the home page after logging out

if __name__ == '__main__': # main function to run the flask app
    init_db() # intilaise the database
    app.run(debug=True) # run the flask app in debugg mode
