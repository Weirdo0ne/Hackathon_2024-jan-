# app.py
from flask import session
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity
import pandas as pd
from pymongo import MongoClient
import requests
from bs4 import BeautifulSoup
from flask import Flask, request, render_template, redirect, url_for, session
from werkzeug.security import generate_password_hash, check_password_hash
from googleapiclient.discovery import build
from flask import render_template
from googleapiclient.discovery import build
import re
import jsonify
from bson import ObjectId
from functools import wraps
import pandas as pd
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt

import seaborn as sns
import io
import base64
from functools import wraps
from flask import session, redirect, url_for
import base64

# Create the Flask app  

app = Flask(__name__)
app.secret_key = "waoiavbodabducwioabovfaoibaoduboawvboryvow"  # Set a secret key for session management

# Connect to MongoDB
client = MongoClient("mongodb+srv://user:user123@cluster0.z5xjddp.mongodb.net/")

# Access the database and collection containing the job data
db = client["database"]
job_data_collection = db["job_data_test"]
skill_video_collection= db["skill_video"]
user_activity_collection= db["user_activity"]


db = client["database"]
skill_video_collection = db["skill_video"]


@app.route('/webdesign')
def webdesign_playlist():
    # Render the template with the embedded YouTube playlist
    return render_template('webdesign.html')

@app.route('/webdeve')
def webdeve_playlist():
    # Render the template with the embedded YouTube playlist
    return render_template('webdeve.html')

@app.route('/healthcare')
def healthcare_playlist():
    # Render the template with the embedded YouTube playlist
    return render_template('healthcare.html')

def admin_required(func):
    @wraps(func)
    def decorated_function(*args, **kwargs):
        if 'username' not in session or session.get('role') != '1':
            return redirect(url_for('login'))  # Redirect to login if not admin
        return func(*args, **kwargs)
    return decorated_function



def get_current_user():
    if 'username' in session:
        return {'username': session['username']}
    else:
        return None

from flask import jsonify

# Assuming you have a function to retrieve user activity data from MongoDB
def get_user_activity_data():
    # Retrieve user activity data from MongoDB
    # Replace this with your implementation to fetch data from MongoDB
    user_activity_data = user_activity_collection.find({})
    data_list = list(data)
    if not data_list:
        return jsonify({"error": "No user activity data available"})
    
    # Process the data as needed
    # For example, extract labels and data for user activity
    labels = [entry['user_id'] for entry in data_list]
    data = [entry['time_spent'] for entry in data_list]

    # Return the processed user activity data
    return jsonify({"labels": labels, "data": data})

# Assuming you have a function to retrieve page visit data from MongoDB
def get_page_visits_data():
    # Retrieve page visit data from MongoDB
    # Replace this with your implementation to fetch data from MongoDB
    data = user_activity_collection.find({})
    data_list = list(data)
    if not data_list:
        return jsonify({"error": "No page visit data available"})
    
    # Process the data as needed
    # For example, extract page URLs and calculate total time spent on each page
    page_visits = {}
    for entry in data_list:
        page_url = entry.get('page_url')
        time_spent = int(entry.get('activity_type').split()[-2]) / 1000  # Extract time spent in seconds
        if page_url in page_visits:
            page_visits[page_url] += time_spent
        else:
            page_visits[page_url] = time_spent
    
    # Extract labels and data for page visits
    labels = list(page_visits.keys())
    data = list(page_visits.values())

    # Return the processed page visit data
    return jsonify({"labels": labels, "data": data})


import base64
from io import BytesIO

@app.route("/admin_panel")
def admin_panel():
    user = get_current_user()

    # Retrieve user activity data from MongoDB and store it in DataFrame df
    # Assuming you already have code to fetch data and store it in df
    collection = db["user_activity"]
    data = collection.find({})
    data_list = list(data)
    df = pd.DataFrame(data_list)

    # Generate charts in memory using matplotlib (avoid saving to files)

    # Plot 1: Time Spent Logged In by User
    df['timestamp'] = pd.to_datetime(df['timestamp'])
    grouped_data = df.groupby('user_id')['timestamp'].agg(lambda x: max(x) - min(x))
    plt.figure(figsize=(10, 6))
    grouped_data.plot(kind='bar')
    plt.xlabel('User ID')
    plt.ylabel('Time Spent Logged In')
    plt.title('Time Spent Logged In by User')

    # Save the plot as a static image
    plot1_buffer = BytesIO()
    plt.savefig(plot1_buffer, format='jpg')
    plt.close()

    # Plot 2: Total Time Spent by User in Each Page
    df['timestamp'] = pd.to_datetime(df['timestamp'])
    df['time_spent'] = df['activity_type'].str.extract(r'(\d+)').astype(float) / 1000
    grouped_data = df.groupby(['user_id', 'page_url'])['time_spent'].sum().unstack()
    plt.figure(figsize=(10, 6))
    grouped_data.plot(kind='bar', stacked=True)
    plt.xlabel('User ID')
    plt.ylabel('Total Time Spent (seconds)')
    plt.title('Total Time Spent by User in Each Page')
    plt.legend(title='Page', bbox_to_anchor=(1.05, 1), loc='upper left')
    plt.tight_layout()

    # Save the plot as a static image
    plot2_buffer = BytesIO()
    plt.savefig(plot2_buffer, format='jpg')
    plt.close()

    # Plot 3: Histogram of Time Spent per Activity
    df['timestamp'] = pd.to_datetime(df['timestamp'])
    df['time_spent'] = df['activity_type'].str.extract(r'(\d+)').astype(float) / 1000
    df['page'] = df['_id'].str.extract(r'-(.*)\d+')
    plt.figure(figsize=(10, 6))
    plt.hist(df['time_spent'], bins=20, color='skyblue', edgecolor='black')
    plt.xlabel('Time Spent (seconds)')
    plt.ylabel('Frequency')
    plt.title('Histogram of Time Spent per Activity')
    plt.grid(True)

    # Save the plot as a static image
    plot3_buffer = BytesIO()
    plt.savefig(plot3_buffer, format='jpg')
    plt.close()

    # Plot 4: Box Plot of Time Spent
    plt.figure(figsize=(10, 6))
    sns.boxplot(y='time_spent', data=df, showfliers=False)
    plt.ylabel('Time Spent (seconds)')
    plt.title('Box Plot of Time Spent')
    plt.grid(True)

    # Save the plot as a static image
    plot4_buffer = BytesIO()
    plt.savefig(plot4_buffer, format='jpg')
    plt.close()

    # Plot 5: Distribution of Time Spent Across Activities
    df['page'] = df['page_url'].str.extract(r'/(.*)')[0]
    total_time_spent = df.groupby('page')['time_spent'].sum()
    plt.figure(figsize=(8, 8))
    plt.pie(total_time_spent, labels=total_time_spent.index, autopct='%1.1f%%', startangle=140)
    plt.title('Distribution of Time Spent Across Activities')

    # Save the plot as a static image
    plot5_buffer = BytesIO()
    plt.savefig(plot5_buffer, format='jpg')
    plt.close()

    # Convert the in-memory buffers to base64 encoded strings
    plot1_base64 = base64.b64encode(plot1_buffer.getvalue()).decode('utf-8')
    plot2_base64 = base64.b64encode(plot2_buffer.getvalue()).decode('utf-8')
    plot3_base64 = base64.b64encode(plot3_buffer.getvalue()).decode('utf-8')
    plot4_base64 = base64.b64encode(plot4_buffer.getvalue()).decode('utf-8')
    plot5_base64 = base64.b64encode(plot5_buffer.getvalue()).decode('utf-8')

    # Define the context for rendering the template
    context = {
        'user': user,
        'plot1': plot1_base64,
        'plot2': plot2_base64,
        'plot3': plot3_base64,
        'plot4': plot4_base64,
        'plot5': plot5_base64
    }

    # Render admin_panel.html template with the context
    return render_template("admin_panel.html", **context)
# Function to extract playlist ID from YouTube playlist li
# Similar routes for web_design and web_development

# Function to check if the provided username and password are valid

@app.route("/logout")
def logout():
    # Clear the session variable to log out the user
    session.pop("username", None)
    return redirect(url_for("login"))

users_collection = db["users"]

def verify_login(username, password):
    user = users_collection.find_one({"username": username})
    if user and user['password'] == password:
        return True
    return False

from flask import request, session, jsonify
from bson import ObjectId
import datetime

def insert_user_activity(activity_type, page_url):
    # Log user activity
    user_id = session.get("user_id", "anonymous")  # Default to "anonymous" if user is not logged in
    if "user_id" in session:
        user_id = session["user_id"]
    timestamp = datetime.datetime.utcnow()
    user_activity = {
        "user_id": user_id,
        "timestamp": timestamp,
        "activity_type": activity_type,
        "page_url": page_url
    }
    # Insert user activity into MongoDB collection
    user_activity_collection.insert_one(user_activity)


@app.route("/log_activity", methods=["POST"])
def log_activity():
    data = request.get_json()
    activity = data.get("activity")
    page = data.get("page")
    
    # Log the activity
    log_user_activity(activity, page)
    
    return jsonify({"message": "Activity logged successfully"})

def log_user_activity(activity_type, page_url):
    # Check if the user is an admin
    if 'username' in session and session['role'] == '1':
        return  # Do not log activity for admins

    # Log user activity for non-admin users
    user_id = session.get("user_id", "anonymous")  # Default to "anonymous" if user is not logged in
    timestamp = datetime.datetime.utcnow()
    user_activity = {
        "user_id": user_id,
        "timestamp": timestamp,
        "activity_type": activity_type,
        "page_url": page_url
    }
    # Insert user activity into MongoDB collection
    user_activity_collection.insert_one(user_activity)


def login_required(func):
    def wrapper(*args, **kwargs):
        if 'username' not in session:
            # If user is not logged in, redirect to the login page
            return redirect(url_for('login'))
        return func(*args, **kwargs)
    return wrapper

@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        name = request.form.get("name")
        email = request.form.get("email")
        username = request.form.get("username")
        password = request.form.get("password")
        secret_question = request.form.get("secret_question")
        
        # Check if any of the required fields are missing
        if not all([name, email, username, password, secret_question]):
            error_message = "Please fill out all required fields."
            return render_template("signup.html", error_message=error_message)
        
        # Check if the username already exists
        if users_collection.find_one({"username": username}):
            error_message = "Username already exists. Please choose a different one."
            return render_template("signup.html", error_message=error_message)
        
        # Insert the user details into the MongoDB collection with hashed password
        users_collection.insert_one({
            "name": name,
            "email": email,
            "username": username,
            "password": password,
            "secret_question": secret_question,
            "role": "0"
        })
        
        # Redirect to login page after successful signup
        return redirect(url_for("login"))
    else:
        return render_template("signup.html")

# Add this route to app.py

@app.route("/reset_password", methods=["GET","POST"])
def reset_password():
    if request.method == "POST":
        username = request.form["username"]
        new_password = request.form["new_password"]
        
        # Update the user's password in the database
        result = users_collection.update_one(
            {"username": username},
            {"$set": {"password": new_password}}
        )
        
        if result.modified_count > 0:
            # Password updated successfully, redirect to login page
            return redirect(url_for("login"))
        else:
            # Failed to update password, display an error message
            error_message = "Failed to reset password. Please try again."
            return render_template("reset_password.html", error_message=error_message)
        
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        # Check if the user is an admin
        if verify_login(username, password):
            user = users_collection.find_one({"username": username})
            if user and user.get("role") == "1":  # Check if user role is admin
                # Authentication successful for admin, set session variables and redirect to admin panel
                session['username'] = username
                session['role'] = user['role']  # Set the user role in the session
                return redirect(url_for("admin_panel"))
            else:
                # Authentication successful for regular user, set session variables and redirect to index
                session['username'] = username
                session['user_id'] = get_username(username)  # Set the user ID in the session
                return redirect(url_for("index"))
        else:
            # Authentication failed, show error message
            error_message = "Invalid username or password"
            return render_template("login.html", error_message=error_message)
    return render_template("login.html")


def get_username(username):
    user = users_collection.find_one({"username": username})
    if user:
        return user["username"]  # Return the username
    return None



# Add this route to app.py
@app.route("/forgot_password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        username = request.form["username"]
        secret_question = request.form["secret_question"]
        
        # Retrieve the user details based on the provided username
        user = users_collection.find_one({"username": username})
        
        if user:
            # Verify if the provided secret question matches the one in the database
            if user["secret_question"] == secret_question:
                # Secret question matches, render a page to reset the password
                return render_template("reset_password.html", username=username)
            else:
                # Secret question doesn't match, display an error message
                error_message = "Secret question does not match."
                return render_template("forgot_password.html", error_message=error_message)
        else:
            # User not found, display an error message
            error_message = "User not found."
            return render_template("forgot_password.html", error_message=error_message)
    
    # Render the forgot password form
    return render_template("forgot_password.html")






def fetch_thumbnail_url(course_link):
    try:
        response = requests.get(course_link)
        if response.status_code == 200:
            soup = BeautifulSoup(response.text, 'html.parser')
            # Example: find the <meta> tag containing the thumbnail URL
            thumbnail_meta_tag = soup.find("meta", property="og:image")
            if thumbnail_meta_tag:
                return thumbnail_meta_tag["content"]
    except Exception as e:
        print(f"Error fetching thumbnail for course link {course_link}: {str(e)}")
    return None
    
@app.route("/")
def ind():
    return redirect(url_for('login'))

@app.route("/index", methods=["GET", "POST"])
def index():
    return render_template("index.html")

# Protected route - profile page
@app.route("/profile", methods=["GET"])
@login_required
def profile():
    # Get the current user's information from the MongoDB collection
    user = users_collection.find_one({"username": session["username"]})
    print("User document from MongoDB:", user)  # Print the user document for debugging
    if user:
        name = user.get("name", "")  # Get the user's name from the database
        email = user.get("email", "")  # Get the user's email from the database
        print("Name:", name)  # Print the name for debugging
        print("Email:", email)  # Print the email for debugging
        return render_template("profile.html", user=user, name=name, email=email)
    else:
        return "User not found"  # Render an error message if user not found



@app.route("/about",methods=["GET","POST"])
def about():
    return render_template("about.html")

@app.route("/contact")
def contact():
    return render_template("contact.html")

# ... rest of the code
@app.route("/courses",methods=["GET","POST"])
def courses():
    return render_template("courses.html")

@app.route("/teacher",methods=["GET","POST"])  
def teacher():
    return render_template("teacher.html")

@app.route("/privacy", methods=["GET","POST"])
def privacy():
    return render_template("privacy.html")

@app.route("/terms", methods=["GET","POST"])
def terms():
    return render_template("term.html")

@app.route("/faq", methods=["GET","POST"])
def faq():
    return render_template("faq.html")

if __name__ == "__main__":
    app.run(debug=True)
