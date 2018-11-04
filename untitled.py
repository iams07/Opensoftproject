from flask import Flask, redirect, url_for, request, session, render_template, g
from passlib.hash import sha256_crypt
import pymysql
import pymysql.cursors
import yaml

app = Flask(__name__)
app.secret_key = 'string'
db = pymysql.connect(host='localhost',
					user='root',
					password='',
					db='user',
					charset='utf8mb4',
					cursorclass=pymysql.cursors.DictCursor
	)
@app.route('/add')
def add():
	if g.user == None:
		return render_template('sign.html')
	return render_template('add.html')
@app.route('/home')
def home():
	if g.user == None:
		return render_template('sign.html')
	return render_template('home.html')
@app.route('/login',methods = ['POST','GET'])
def login():
	if request.method == 'POST':
		session.pop('user', None)
		na = request.form['na']
		user = request.form['user']
		email = request.form['email']
		pword = request.form['pass']
		rpword = request.form['repass']
		if pword == rpword:
				cursor = db.cursor()
				cursor.execute("SELECT * FROM user WHERE username = %s", user)
				row = cursor.fetchone()
				if row:
					return 'Username already taken'
				else:
					pword = sha256_crypt.hash(pword)
					session['user'] = request.form['user']
					session['name'] = request.form['na']
					session['email'] = request.form['email']
					cursor.execute("INSERT INTO user(name,username,email,password) VALUES(%s, %s, %s, %s)",(na,user,email,pword))
					cursor.execute("INSERT INTO cab(username) VALUES(%s)",(user))
					cursor.connection.commit()
					cursor.close()
					return redirect(url_for('protected'))
		else:
			return 'Passwords do not match'
	return render_template('login.html')

@app.route('/protected')
def protected():
	if g.user == None:
		return redirect(url_for('sign'))
	return render_template('home.html')

@app.route('/sign',methods= ['POST','GET'])
def sign():
	if request.method == 'POST':
		session.pop('user', None)
		user = request.form['user']
		pword = request.form['pass']
		cursor = db.cursor()
		cursor.execute("SELECT * FROM user WHERE username = %s",user)
		row = cursor.fetchone()
		psw = row['password']
		if row:
			if sha256_crypt.verify(pword, psw):
				na = row['name']
				email = row['email']
				session['user'] = request.form['user']
				session['name'] = row['name']
				session['email'] = row['email']
				return redirect(url_for('protected'))
			else:
				return '%s is Incorrect password' % pword
		else:
			return 'Username %s does not exist' % user
	return render_template('sign.html')

@app.route('/cabadd')
def cabadd():
	if request.method == 'POST':
		user = session['user']
		start = request.form['start']
		end = request.form['end']
		date = request.form['date']
		time = request.form['time']
		number = request.form['num']
		cursor = db.cursor()
		cursor.execute("INSERT INTO cab(contact) VALUES(%d) WHERE username = %s",(number), user)
		cursor.connection.commit()
		cursor.close()
	return redirect(url_for("add"))

@app.before_request
def before_request():
	g.user = None
	if 'user' in session:
		g.user = session['user']
		g.name = session['name']
		g.email = session['email']
@app.route('/logout')
def logout():
	session.pop('user', None)
	session.pop('name', None)
	session.pop('email', None)
	g.user = None
	g.email = None
	g.name = None
	return render_template('sign.html')
if __name__ == '__main__':
	app.debug = True
	app.run()
	app.run(debug = True)