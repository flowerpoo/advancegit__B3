from flask import Flask,flash, render_template, url_for,request,session,redirect
import pymongo
from bson import ObjectId
import bcrypt
import os,re
import ast
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
        user_id = session['userid']
        #print(user_id)
        taskname = request.form['taskname']
        description = request.form['description']
        task_exist = db.task_info.find_one({"taskname":taskname})
        #use= db.user_info.finf_one({"_id": ObjectId(id)})
        user_email= session['email']
        #db.task_info.insert_many([{'taskname': taskname ,'description': description}])
        if task_exist:
            mesage = 'Task name already exists ! please try other something new'
        else:
            db.task_info.insert_many([{'taskname': taskname ,'description': description,'assigned_user': user_email}])
            mesage= 'You have successfully added task!'
            return redirect(url_for('tasks'))
       # return redirect(url_for('tasks'))
    return render_template('addtask.html', mesage=mesage)
      
@app.route("/edittask", methods=['GET','POST','PUT'])
def edittask():
    if 'loggedin' in session:
        id = request.values.get('_id')
        #print(id)
        tas=db.task_info.find({"_id": ObjectId(id)})
        #print(tas)
        all_user=db.user_info.find({})
        print(all_user)
        #if request.method == 'POST':
         #   taskna=request.form['taskname']
          #  taskde=request.form['description']
           # t= db.task_info.find_one({"tashname" :taskna})
            #task_id=str(t['_id'])
            #db.task_info.update([{'taskname': taskna ,'description': taskde}])
            #return redirect(url_for('tasks'))
        return render_template('edittask.html', tasks=tas,id=id,all_user=all_user)

           
@app.route("/edittask1", methods=['POST','GET'])
def edittask1():
    taskname = request.values.get('taskname')
    #taskname = request.form['taskname']
    rows=[]
    description = request.values.get('description')
    #email= ast.literal_eval(request.form.get('assigned_task'))
    email=request.form.get('assigned_user')
    print(email)
    #check selected email user id 
    
    #cursor = object_collection.find({"email":1})
    #for document in cursor:
     #   rows.append(document['email'])
    #cursor= db.user_info.find_one({})
    # description = request.form['description']
    #all_user=db.user_info.find({})
    #print(all_user)
    id= request.values.get('_id')
    #print(id)
    db.task_info.update_many({"_id": ObjectId(id)}, {'$set': {'taskname': taskname ,'description': description,'assigned_user': email}})
    return redirect(url_for('tasks'))
    

@app.route("/deletetask",methods=['GET','POST'])
def deletetask():
    if 'loggedin' in session:
        
        
        id= request.values.get('_id')
        print(id)
        
        db.task_info.delete_one({"_id": ObjectId(id)})
        return redirect (url_for('tasks'))


        


if __name__ == "__main__":
    app.run(debug=True)