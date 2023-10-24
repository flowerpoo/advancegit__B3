from flask import Flask,flash, render_template, url_for,request,session,redirect
import pymongo
import bcrypt
import os,re

app = Flask(__name__)
app.secret_key = "testing"


mongodb_client=pymongo.MongoClient("mongodb+srv://admin:Advancegit__B3@cluster0.v7xpfsi.mongodb.net/?retryWrites=true&w=majority")
#client=mongodb_client.get_database('user_info')
db=mongodb_client.get_database('user_info') #data base selected
db=db # collection name
db_task=mongodb_client.get_database('user_info')
db=db_task




@app.route("/register", methods =['GET','POST'])
def register():
    mesage = ' '
    if request.method == 'POST' and 'name' in request.form and 'password' in request.form and 'email' in request.form :
        fullname = request.form['name']
        password = request.form['password']
        email = request.form['email']
         
        user_exists = db.user_info.find_one({"email":email})
        #print(fullname)
        #print(password)
        #print(email)
        #flash('You were successfully logged in')
        
        if user_exists:
            mesage = 'Email already exists !'
        elif not re.match(r'[^@]+@[^@]+\.[^@]+', email):
            mesage = 'Invalid email address !'
        elif not fullname or not password or not email:
            mesage = 'Please fill out the form !'
        else:
            #hashed_password = bcrypt.generate_password_hash(password)
            hashed_password=bcrypt.hashpw(password.encode('utf-8'),bcrypt.gensalt())
            #new_user = Users(name=fullname, email=email, password=hashed_password)
           # db.session.add(new_user)
            #db.session.commit()
            db.user_info.insert_many([{'name':fullname,'email':email,'password':hashed_password}])
            mesage= 'You have successfully registered !'
    elif request.method == 'POST':
        mesage = 'Please fill out the form !'
    return render_template('register.html', mesage=mesage)

@app.route("/")
@app.route('/login', methods=['GET', 'POST'])
def login():
    mesage=''
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        #print(email)
        #print(password)
        if email == '' or password == '':
            mesage = 'please enter email and password'
        else:
            user = db.user_info.find_one({"email":email})
            #print(user)
            passwordcheck = user['password']
            #print(user['_id'])
            use_id = str(user['_id'])
            #print(use_id)
            #d =[]
            #objectid = str(ObjectId(user['_id']))

            if user is None:
                mesage = "please enter correct email"
            else:
                if not bcrypt.checkpw(password.encode('utf-8'), passwordcheck):
                    mesage = "please enter correct mail Id and password"
                else:
                    session['loggedin'] = True
                    session['userid'] = use_id
                    session['name'] = user['name']
                    session['email'] = user['email']
                    mesage = 'Logged in succesfully'
                    return redirect(url_for('dashboard'))
                    
            
        
    return render_template('login.html', mesage=mesage)

@app.route("/dashboard", methods=['GET','POST'])
def dashboard():
    if 'loggedin' in session:        
        return render_template("dashboard.html")
    return redirect(url_for('login'))

@app.route('/logout')
def logout():
    session.pop('loggedin', None)
    session.pop('userid', None)
    session.pop('email', None)
    return redirect(url_for('login')) 

@app.route("/tasks", methods=['GET','POST'])
def tasks():
    if 'loggedin' in session:
        all_task=db.task_info.find({})
        return render_template("tasks.html", task= all_task)
    return redirect(url_for('login'))
    
@app.route('/addtask', methods=['GET','POST'])
def addtask():
    mesage=''
    if request.method == 'POST' and 'taskname' in request.form and 'description' in request.form:
        taskname = request.form['taskname']
        description = request.form['description']
        task_exist = db.task_info.find_one({"taskname":taskname})
        #db.task_info.insert_many([{'taskname': taskname ,'description': description}])
        if task_exist:
            mesage = 'Task name already exists ! please try other something new'
        else:
            db.task_info.insert_many([{'taskname': taskname ,'description': description}])
            mesage= 'You have successfully added task!'
            return redirect(url_for('tasks'))
       # return redirect(url_for('tasks'))
    return render_template('addtask.html', mesage=mesage)
       # message=''
        #if 'loggedin' in session:
          #  if request.method == 'POST' and 'taskname' in request.form and 'description' in request.form:
             #   taskname = request.form['taskname']
               # description = request.form['description']
               # db.task_info.insert_many([{'taskname': taskname ,'description': description}])
               # return redirect(url_for('tasks'))
"""task_exist = db.user_info.find_one({"taskname":taskname})
            if taskname == '' or description == '':
                message("please fill the form ")
            else:
                if task_exist:
                    mesage = 'Task name already exists ! please try other something new'
                else:
                    db.task_info.insert_many([{'taskname': taskname ,'description': description}])
                    message= 'You have successfully added task!'
                    return redirect(url_for('tasks'))"""
      
        


if __name__ == "__main__":
    app.run(debug=True)

"""from flask import Flask, render_template, url_for,request,session,redirect
import pymongo
import bcrypt

app = Flask(__name__)
app.secret_key = "testing"


mongodb_client=pymongo.MongoClient("mongodb+srv://admin:Advancegit__B3@cluster0.v7xpfsi.mongodb.net/?retryWrites=true&w=majority")
#client=mongodb_client.get_database('user_info')
db=mongodb_client.get_database('user_info')
db=db

@app.route('/register',methods=['POST','GET'])
def register():
    message=''
    if request.method == 'POST':
        n=request.form.get('name')
        e= request.form.get('email')
        p= request.form.get('password')
        ph= request.form.get('phone')
        email_found = db.user_info.find_one({"email":e})
        if email_found:
            message="email id already exist"
            return render_template('login.html',message=message)
        else:
            #hash password
            hashed=bcrypt.hashpw(p.encode('utf-8'),bcrypt.gensalt())
            #assign them in dictonary key value pairs
            #user = {'name':n,'email':e,'phone':ph,'password':hashed}
            db.user_info.insert_many([{'name':n,'email':e,'phone':ph,'password':hashed}])
            #insert in db
            #db.user_info.insert_many(user)
            return render_template("dashboard.html")
      # db.user_info.insert_many([{'name':n,'email':e,'phone':ph,'password':p }])
    return render_template("register.html")
    

@app.route('/',methods=['POST','get'])
def login():
    message=''
    if "email" in session:
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        email = request.form.get("email")
        password= request.form.get("password")
        email_found=db.user_info.find_one({"email":email})
        if email_found:
            email_val=email_found['email']
            passwordcheck=email_found['password']
            #encode password matches check
            if bcrypt.checkpw(password.encode('utf-8'), passwordcheck):
                session["email"] = email_val
                return redirect(url_for('dashboard'))
            else:
                mesage = 'Wrong password'
                return render_template('login.html', message=message)
            #if passwordcheck == password:
                #return redirect(url_for('dashboard'))
            #else:
                #mesage = 'Wrong password'
                #return render_template('login.html', message=message)
        else:
            message='Email not foiund'
            return render_template('login.html',message=message)

    return render_template ('login.html')


  
@app.route('/dashboard',methods=['POST','GET'])
def dashboard():
    if "email" in session:
        email=session["email"]
        return render_template('dashboard.html', email=email)
    else:
        return redirect(url_for("login"))  
    return render_template('dashboard.html')

@app.route('/logout', methods=['POST,"GET'])
def logout():
    if "email" in session:
        session.pop("email", None)
        return render_template('logout.html')
    else:
        return render_template('login.html')                              

if __name__ == "__main__":
    app.run(debug=True) """

"""client = pymongo.MongoClient("mongodb+srv://admin:Advancegit__B3@cluster0.v7xpfsi.mongodb.net/?retryWrites=true&w=majority")
db = client.get_database('total_records')
records = db.register

@app.route("/",methods=['post', 'get'])
def index():
    mesage = ''
    if "email" in session:
        return redirect(url_for("logged_in"))
    if request.method == "POST":
        user = request.form.get("fullname")
        email = request.form.get("email")
        
        password1 = request.form.get("password1")
        password2 = request.form.get("password2")
        
        user_found = records.find_one({"name": user})
        email_found = records.find_one({"email": email})
        if user_found:
            mesage = 'There already is a user by that name'
            return render_template('index.html', message=message)
        if email_found:
            mesage = 'This email already exists in database'
            return render_template('index.html', message=message)
        if password1 != password2:
            mesage = 'Passwords should match!'
            return render_template('index.html', message=message)
        else:
            hashed = bcrypt.hashpw(password2.encode('utf-8'), bcrypt.gensalt())
            user_input = {'name': user, 'email': email, 'password': hashed}
            records.insert_one(user_input)
            
            user_data = records.find_one({"email": email})
            new_email = user_data['email']
   
            return render_template('logged_in.html', email=new_email)
    return render_template('index.html')

@app.route("/dashboard")
def dashboard():
    return render_template('dashboard.html')

@app.route("/register",methods=['post', 'get'])
def register():
    return render_template('register.html',reg_home2 = url_for('dashboard'))


if __name__ == "__main__":
    app.run(debug=True)
"""
"""task_exist = db.user_info.find_one({"taskname":taskname})
            if taskname == '' or description == '':
                message("please fill the form ")
            else:
                if task_exist:
                    mesage = 'Task name already exists ! please try other something new'
                else:
                    db.task_info.insert_many([{'taskname': taskname ,'description': description}])
                    message= 'You have successfully added task!'
                    return redirect(url_for('tasks'))"""