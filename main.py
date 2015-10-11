import os
import hashlib
import hmac
import re
import random
import string
import time
import MySQLdb
import uuid
import datetime
import signal
import logging

import tornado.ioloop
import tornado.web
from tornado.options import options
from jinja2 import Environment, FileSystemLoader

template_dir=os.path.join(os.path.dirname(__file__),'templates')
jinja_env=Environment(loader=FileSystemLoader(template_dir),autoescape=True)

db = MySQLdb.connect(host="localhost",user="test",passwd="password",db="test2"
					,use_unicode=True,charset="utf8")
cur=db.cursor()

is_closing = False
def signal_handler(signum, frame):
	global is_closing
	logging.info('exiting...')
	is_closing = True

def try_exit(): 
	global is_closing
	if is_closing:
		tornado.ioloop.IOLoop.instance().stop()
		logging.info('exit success')

def get_size(filename):
	st=os.stat(filename)
	return st.st_size

def size_format(num):
	for unit in ['','Ki','Mi','Gi','Ti','Pi','Ei','Zi']:
		if num < 1024.0:
			if unit=='' :
				return "%s B" % (num)
			return "%.1f %s%s" % (num,unit,'B')
		num /= 1024.0
	return "%.1f%s%s" % (num,'Yi','B')

def make_salt():
	return ''.join(random.choice(string.letters) for x in xrange(5))
def make_password_hash(name, pw, salt=None):
	if not salt :
		salt = make_salt()
	h = hashlib.sha256(name + pw + salt).hexdigest()
	return '%s,%s' % (h, salt)
def valid_password(name, pw, h):
	arr=h.split(',')
	if len(arr)==2 and h==make_password_hash(name,pw,arr[1]) :
		return True

user_re=re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
password_re=re.compile(r"^.{3,20}$")
email_re=re.compile(r"^[\S]+@[\S]+\.[\S]+$")

class File :
	def __init__(self,name,user,uuid,size,created=None):
		self.name=name
		self.user=user
		self.uuid=uuid
		self.size=size
		if not created :
			created=datetime.datetime.now()
		self.created=created
	def put(self):
		cur.execute("INSERT INTO Upload VALUES ('%s','%s','%s','%s','%s')" % \
					(self.name,self.user,self.uuid,self.size,self.created))
		db.commit()

	@classmethod
	def to_file(cls,arr):
		ret=[]
		for i in arr :
			ret.append(File(i[0],i[1],i[2],i[3],i[4]))
		return ret

class User:
	def __init__(self,u,p,e) :
		self.username=u
		self.password_hash=p
		self.email=e

	def put(self):
		cur.execute("INSERT INTO User (username,password_hash,email) VALUES \
					('%s','%s','%s')" % (self.username,self.password_hash,self.email))
		db.commit()
	def get_id(self):
		cur.execute("SELECT id FROM User WHERE username='%s'" % self.username)
		ids=cur.fetchall()
		if len(ids)>0 :
			return ids[0][0]

	@classmethod
	def get_by_id(cls,idx):
		cur.execute("SELECT * FROM User WHERE id=%s" % idx)
		users=User.to_user(cur.fetchall())
		if len(users)>0 :
			return users[0]

	@classmethod
	def to_user(cls,arr):
		ret=[]
		for i in arr :
			ret.append(User(i[1],i[2],i[3]))
		return ret

	@classmethod
	def find_by_name(cls,name):
		cur.execute("SELECT * FROM User WHERE username='%s'" % name)
		users=User.to_user(cur.fetchall())
		if(len(users)>0) :
			return users[0]

	@classmethod
	def get_error_message(cls,u,p,v,e): # check if user's input is valid
		uerr="" ; perr="" ; verr="" ; eerr="" ; # and return error message
		err=0
		if (not u.isalpha()) or (not user_re.match(u)) :
			err=1
			uerr="That's not a valid username"
		elif User.find_by_name(u) :
			err=1
			uerr="This username already exist!"
		if not password_re.match(p) :
			err=1
			perr="That's not a valid password"
		if v!=p :
			err=1
			verr="Your passwords didn't match"
		if e and (not email_re.match(e)) :
			err=1
			eerr="That's not a valid email"
		return err,[uerr,perr,verr,eerr]

	@classmethod
	def login(cls,username,password):
		user=User.find_by_name(username)
		if user and valid_password(username,password,user.password_hash) :
			return user

__UPLOADS__ = "uploads/"
def process_new_user(u,p,e):
	user=User(u,make_password_hash(u,p),e)
	user.put()
	os.mkdir(__UPLOADS__ + u)
	return user

class Handler(tornado.web.RequestHandler):
	def render_str(self,template,**params):
		t=jinja_env.get_template(template)
		return t.render(params)
	def render(self,template,**kw):
		self.write(self.render_str(template,**kw))
	def login(self,user):
		self.set_secure_cookie('user_id',str(user.get_id()))
	def prepare(self):
		user_id=self.get_secure_cookie('user_id')
		if user_id :
			self.user=User.get_by_id(int(user_id))
		else:
			self.user=None
	def logout(self):
		self.clear_cookie('user_id')
	def get_argument(self,arg) :
		arr=self.get_arguments(arg)
		if len(arr)>0 :
			return arr[0]
	def get_multiple_argument(self,*a) :
		ret=[]
		for i in a :
			ret.append(self.get_argument(i))
		return ret

class MainHandler(Handler):
	def get(self):
		self.render("index.html",upload_message="",user=self.user)

class SignupHandler(Handler):
	def render_html(self,username="",email="",username_error="",
					password_error="",verify_error="",email_error=""):
		self.render("signup.html",username=username,email=email,
					username_error=username_error,password_error=password_error,
					verify_error=verify_error,email_error=email_error)
	def get(self):
		self.render_html()
	def post(self):
		u,p,v,e = self.get_multiple_argument('username','password','verify','email')
		err,message = User.get_error_message(u,p,v,e)
		if err==0 :
			user=process_new_user(u,p,e)
			self.login(user)
			self.redirect('/')
		else :
			self.render_html(u,e,*message)

class LoginHandler(Handler):
	def get(self):
		if self.user:
			self.redirect("/")
		else :
			self.render("login.html",login_error="")
	def post(self):
		username,password = self.get_multiple_argument('username','password')
		user=User.login(username,password)
		if user :
			self.login(user)
			self.redirect('/')
		else :
			self.render("login.html",login_error="Invalid Login")

class LogoutHandler(Handler):
	def get(self):
		self.logout()
		self.redirect('/login')

class FileUploadHandler(Handler):
	def render_html(self,upload_message=""):
		self.render("index.html",upload_message=upload_message,user=self.user)
	def post(self):
		fileinfo = self.request.files.get('filearg')
		if not fileinfo :
			self.render_html("Please select a file.")
		elif not self.user :
			self.render_html("Please login first.")
		else :
			username=self.user.username
			fileinfo=fileinfo[0]
			fname = fileinfo['filename']
			uid=str(uuid.uuid4())
			fullname=__UPLOADS__ + username + '/' + uid
			with open(fullname, 'w') as fh :
				fh.write(fileinfo['body'])

			f=File(fname,username,uid,get_size(fullname))
			f.put()
			self.render_html("Upload Sucessed!")

class FileHandler(Handler):
	def render_html(self,rename):
		username=self.user.username
		cur.execute('SELECT * FROM Upload WHERE user="%s" \
					ORDER BY created DESC' % username)
		files=File.to_file(cur.fetchall())
		total_size=0
		for i in range(0,len(files)) :
			f=files[i]
			total_size+=f.size
			f.size=size_format(f.size)
			files[i]=f
		self.render("files.html",files=files,user=self.user,
								total_size=size_format(total_size),rename=rename)
	def get(self,uid):
		if not self.user :
			self.redirect('/login')

		cur.execute("SELECT name FROM Upload WHERE uuid='%s'" % uid[1:])
		files=list(cur.fetchall())
		if len(files)>0 :
			filename = files[0][0]
			username=self.user.username
			self.set_header('Content-Type', 'application/octet-stream')
			self.set_header('Content-Disposition', 'attachment; filename=' + filename)
			buf_size = 4096
			with open(__UPLOADS__ + username + uid, 'r') as f:
				while True:
					data = f.read(buf_size)
					if not data:
						break
					self.write(data)
		elif uid=='/' :
				rename=self.get_argument('rename')
				self.render_html(rename)
		else :
			self.redirect('/files/')

	def post(self,uid):
		if not self.user :
			self.rediect('/login')
		username=self.user.username

		action=self.get_argument('action')
		if not action :
			self.redirect('/')

		elif action=="delete" :
			file_path = __UPLOADS__ + username + uid
			if os.path.exists(file_path) :
				cur.execute("DELETE FROM Upload WHERE uuid='%s'" % uid[1:])
				os.remove(file_path)
				db.commit()
			self.redirect('/files/')

		elif action=="rename" :
			newname=self.get_argument('newname')
			uid=self.get_argument('uuid')
			if (newname==None) or (not uid) :
				self.redirect('/')
			elif len(newname)>0 :
				cur.execute("UPDATE Upload SET name='%s' WHERE uuid='%s'" % \
							(newname,uid))
				db.commit()
				self.redirect("/files/")
			else :
				self.redirect("/files/")
		else :
			self.redirect('/')


PAGE_RE = r'(/(?:[a-zA-Z0-9_-]+/?)*)'
application = tornado.web.Application([
	(r"/", MainHandler),
	(r"/signup", SignupHandler) ,
	(r"/login", LoginHandler) ,
	(r"/logout", LogoutHandler) ,
	(r"/fileupload", FileUploadHandler) ,
	(r"/files" + PAGE_RE,FileHandler) ,
],debug=True,cookie_secret="Hello, world !!! XDD")

if __name__ == "__main__":
	tornado.options.parse_command_line()
	signal.signal(signal.SIGINT, signal_handler)
	application.listen(8888)
	tornado.ioloop.PeriodicCallback(try_exit, 100).start() 
	tornado.ioloop.IOLoop.instance().start()