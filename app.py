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
      

      
        


if __name__ == "__main__":
    app.run(debug=True)