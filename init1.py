#Import Flask Library
from fnmatch import fnmatchcase
from flask import Flask, render_template, request, session, url_for, redirect, flash
import pymysql.cursors

#for uploading photo:
from app import app
#from flask import Flask, flash, request, redirect, render_template
from werkzeug.utils import secure_filename

import hashlib
import secrets
SALT = 'z2x4c6'

ALLOWED_EXTENSIONS = set(['png', 'jpg', 'jpeg', 'gif'])


###Initialize the app from Flask
##app = Flask(__name__)
##app.secret_key = "secret key"

#Configure MySQL
conn = pymysql.connect(host='localhost',
                       port = 3307,
                       user='root', #replace with your db username
                       password='root', #replace with your password
                       db='Finstagram',  #replace with your db name
                       charset='utf8mb4',
                       cursorclass=pymysql.cursors.DictCursor)


def allowed_image(filename):

    if not "." in filename:
        return False

    ext = filename.rsplit(".", 1)[1]

    if ext.upper() in app.config["ALLOWED_IMAGE_EXTENSIONS"]:
        return True
    else:
        return False


def allowed_image_filesize(filesize):

    if int(filesize) <= app.config["MAX_IMAGE_FILESIZE"]:
        return True
    else:
        return False


#Define a route to hello function
@app.route('/')
def hello():
    return render_template('index.html')


#Define route for login
@app.route('/login')
def login():
    return render_template('login.html')


#Define route for register
@app.route('/register')
def register():
    return render_template('register.html')


#Authenticates the login
@app.route('/loginAuth', methods=['GET', 'POST'])
def loginAuth():
    #grabs information from the forms
    username = request.form['username']
    password = request.form['password'] + SALT
    hashed_password = hashlib.sha256(password.encode('utf-8')).hexdigest()


    #cursor used to send queries
    cursor = conn.cursor()
    #executes query
    query = 'SELECT * FROM person WHERE username = %s and password = %s'   
    cursor.execute(query, (username, hashed_password))
    #stores the results in a variable
    data = cursor.fetchone()
    #use fetchall() if you are expecting more than 1 data row
    cursor.close()
    error = None
    if(data):
        #creates a session for the the user
        #session is a built in
        session['username'] = username
        return redirect(url_for('home'))
    else:
        #returns an error message to the html page
        error = 'Invalid login or username'
        return render_template('login.html', error=error)


#Authenticates the register
@app.route('/registerAuth', methods=['GET', 'POST'])
def registerAuth():
    #grabs information from the forms
    username = request.form['username']
    password = request.form['password'] + SALT
    hashed_password = hashlib.sha256(password.encode('utf-8')).hexdigest()
    fname = request.form['first name']
    lname = request.form['last name']
    email = request.form['email']

    #cursor used to send queries
    cursor = conn.cursor()
    #executes query
    query = 'SELECT * FROM person WHERE username = %s'   
    cursor.execute(query, (username))
    #stores the results in a variable
    data = cursor.fetchone()
    #use fetchall() if you are expecting more than 1 data row
    error = None
    if(data):
        #If the previous query returns data, then user exists
        error = "This user already exists" 
        return render_template('register.html', error = error)
    else:
        ins = 'INSERT INTO person VALUES(%s, %s, %s, %s, %s)'  
        cursor.execute(ins, (username, hashed_password, fname, lname, email))
        conn.commit()
        cursor.close()
        return render_template('index.html')


@app.route('/home')
def home():
    user = session['username']
    cursor = conn.cursor();
    # not yet implemented: include pids from followees if allFollowers = true 
    query = 'SELECT postingDate, pid FROM sharedWith NATURAL JOIN belongTo NATURAL JOIN photo WHERE username = %s ORDER BY postingDate DESC' 
    cursor.execute(query, (user))
    data = cursor.fetchall()
    query = 'SELECT follower FROM follow JOIN person ON follow.followee = person.username WHERE username = %s AND followStatus = 0'
    cursor.execute(query, (user))
    r_data = cursor.fetchall()
    cursor.close()
    return render_template('home.html', username=user, posts=data, requests=r_data)

        
@app.route('/friend_request')
def friend_request():
    return render_template('friend_request.html')

    
@app.route('/friend_request_auth', methods=['GET', 'POST'])
def friend_request_auth():
    user = session['username']
    cursor = conn.cursor();
    followee = request.form['followee']

    query = 'SELECT * FROM person WHERE username = %s'   
    cursor.execute(query, (followee))
    data = cursor.fetchone()
    error = None
    if(data):
        ins = 'INSERT INTO follow (follower, followee, followStatus) VALUES(%s, %s, 0)'
        cursor.execute(ins, (user, followee))
        conn.commit()
        cursor.close()
        return redirect(url_for('home'))  
    else:
        # if the previous query is empty, user does not exist
        error = "This user does not exist" 
        return render_template('friend_request.html', error = error) # need to redirect with error


@app.route('/friend_group')
def friend_group():
    return render_template('friend_group.html')


@app.route('/friend_group_auth', methods=['GET', 'POST'])
def friend_group_auth():
    user = session['username']
    group_name = request.form['group_name']
    desc = request.form['description']
    cursor = conn.cursor();
    query = 'SELECT * FROM friendgroup WHERE groupName = %s AND groupCreator = %s'
    cursor.execute(query, (group_name, user))
    data = cursor.fetchone()
    error = None
    if(data):
        #If the previous query returns data, then group exists
        error = "This group already exists" 
        return render_template('friend_group.html', error = error)
    else:
        ins = 'INSERT INTO friendgroup VALUES(%s, %s, %s)'  
        cursor.execute(ins, (group_name, user, desc))
        ins = 'INSERT INTO belongto VALUES(%s, %s, %s)'
        cursor.execute(ins, (user, group_name, user))
        conn.commit()
        cursor.close()
        return redirect(url_for('home'))


@app.route('/request_accepted', methods=['GET', 'POST'])
def request_accepted():
    user = session['username']
    follower = request.form['action']
    cursor = conn.cursor()
    query = 'UPDATE follow SET followStatus = 1 WHERE follow.follower = %s AND follow.followee = %s'   
    cursor.execute(query, (follower, user))
    conn.commit()
    cursor.close()
    return redirect(url_for('home'))


@app.route('/request_rejected', methods=['GET', 'POST'])
def request_rejected():
    user = session['username']
    follower = request.form['action']
    cursor = conn.cursor()
    query = 'DELETE FROM follow WHERE follower = %s AND followee = %s'   
    cursor.execute(query, (follower, user))
    conn.commit()
    cursor.close()
    return redirect(url_for('home'))


def allowed_file(filename):
	return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS
	

@app.route('/upload_photo')
def upload_photo():
	return render_template('upload.html')


@app.route('/', methods=['POST'])
def upload_file():
	if request.method == 'POST':
        # check if the post request has the file part
		if 'file' not in request.files:
			flash('No file part')
			return redirect(request.url)
		file = request.files['file']
		if file.filename == '':
			flash('No file selected for uploading')
			return redirect(request.url)
		if file and allowed_file(file.filename):
			filename = secure_filename(file.filename)
# system call to save file:
#			file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
			flash('File successfully uploaded')
			return redirect('/')
		else:
			flash('Allowed file types are txt, pdf, png, jpg, jpeg, gif')
			return redirect(request.url)


@app.route('/logout')
def logout():
    session.pop('username')
    return redirect('/')


def shutdown_server():
    func = request.environ.get('werkzeug.server.shutdown')
    if func is None:
        raise RuntimeError('Not running with the Werkzeug Server')
    func()


@app.route('/shutdown', methods=['POST'])
def shutdown():
    shutdown_server()
    return 'Server shutting down...'


key = secrets.token_urlsafe(16)
app.secret_key = key
#Run the app on localhost port 5000
#debug = True -> you don't have to restart flask
#for changes to go through, TURN OFF FOR PRODUCTION
if __name__ == "__main__":
    app.run('127.0.0.1', 5000, debug = True)
