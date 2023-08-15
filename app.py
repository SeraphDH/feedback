from flask import Flask, render_template, redirect, url_for, flash, session, request 
from forms import RegistrationForm, LoginForm
from flask_bcrypt import Bcrypt
from models import User, Feedback, db

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql:///feedback'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ECHO'] = True
app.config['SECRET_KEY'] = "Blahblah"
app.config['DEBUG_TB_INTERCEPT_REDIRECTS'] = False
app.config['DEBUG'] = True

# Initialize Bcrypt
bcrypt = Bcrypt(app)

# Configure the app to use the db object
db.init_app(app)

# Create the tables within the app context
with app.app_context():
    db.create_all()

def create_user(username, password, email, first_name, last_name):
    password_hash = bcrypt.generate_password_hash(password).decode('utf-8')
    new_user = User(
        username=username,
        password_hash=password_hash,
        email=email,
        first_name=first_name,
        last_name=last_name
    )
    return new_user

@app.route('/')
def index():
    return render_template('homepage.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        new_user = create_user(
            username=form.username.data,
            password=form.password.data,
            email=form.email.data,
            first_name=form.first_name.data,
            last_name=form.last_name.data
        )
        db.session.add(new_user)
        db.session.commit()
        flash('User registered successfully!', 'success')
        
        # Redirect to the user profile page, passing the username parameter
        return redirect(url_for('user_profile', username=new_user.username))
    
    return render_template('register.html', form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    # Check if the user is already logged in
    if 'username' in session:
        flash('You are already logged in.', 'info')
        return redirect(url_for('user_profile', username=session['username']))
    
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if user.check_password(bcrypt, form.password.data):
                session['username'] = form.username.data  # Store the username in the session
                flash('Login successful!', 'success')
                return redirect(url_for('user_profile', username=form.username.data))
            else:
                flash('Incorrect password. Please try again.', 'danger')
        else:
            flash('Username not found. Please check your username and try again.', 'danger')
    return render_template('login.html', form=form)

@app.route('/users/<username>')
def user_profile(username):
    if 'username' in session and session['username'] == username:
        user = User.query.filter_by(username=username).first()
        if user:
            feedbacks = Feedback.get_feedback_by_user(user.id)
            return render_template('user_profile.html', user=user, feedbacks=feedbacks)
        else:
            flash('User not found.', 'danger')
            return redirect(url_for('logout'))
    else:
        flash('You need to log in to access this page.', 'danger')
        return redirect(url_for('login'))

@app.route('/logout', methods=['GET'])
def logout():
    session.clear()  # Clear the session
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/users/<username>/feedback/add', methods=['GET'])
def add_feedback_form(username):
    if 'username' in session and session['username'] == username:
        user = User.query.filter_by(username=username).first()
        if user:
            return render_template('add_feedback.html')
    flash('You need to log in to access this page.', 'danger')
    return redirect(url_for('login'))

@app.route('/users/<username>/feedback/add', methods=['POST'])
def add_feedback(username):
    if 'username' in session and session['username'] == username:
        user = User.query.filter_by(username=username).first()
        if user:
            title = request.form.get('title')
            content = request.form.get('content')
            new_feedback = Feedback(title=title, content=content, user=user)
            db.session.add(new_feedback)
            db.session.commit()
            flash('Feedback added successfully!', 'success')
            return redirect(url_for('user_profile', username=session['username']))
    flash('You need to log in to access this page.', 'danger')
    return redirect(url_for('login'))

@app.route('/feedback/<int:feedback_id>/update', methods=['GET'])
def edit_feedback_form(feedback_id):
    feedback = Feedback.query.get_or_404(feedback_id)
    if 'username' in session and session['username'] == feedback.user.username:
        return render_template('edit_feedback.html', feedback=feedback)
    elif 'username' in session and User.query.filter_by(username=session['username'], is_admin=True).first():
        return render_template('edit_feedback.html', feedback=feedback)
    else:
        flash('You do not have permission to access this page.', 'danger')
        return redirect(url_for('login'))

@app.route('/feedback/<int:feedback_id>/update', methods=['POST'])
def edit_feedback(feedback_id):
    feedback = Feedback.query.get_or_404(feedback_id)
    if 'username' in session and session['username'] == feedback.user.username:
        new_title = request.form.get('title')
        new_content = request.form.get('content')
        feedback.title = new_title
        feedback.content = new_content
        db.session.commit()
        flash('Feedback updated successfully!', 'success')
        return redirect(url_for('user_profile', username=session['username']))
    flash('You do not have permission to access this page.', 'danger')
    return redirect(url_for('login'))

@app.route('/feedback/<int:feedback_id>/delete', methods=['GET'])
def delete_feedback_form(feedback_id):
    feedback = Feedback.query.get_or_404(feedback_id)
    if 'username' in session and session['username'] == feedback.user.username:
        return render_template('delete_feedback.html', feedback=feedback)
    elif 'username' in session and User.query.filter_by(username=session['username'], is_admin=True).first():
        return render_template('delete_feedback.html', feedback=feedback)
    else:
        flash('You do not have permission to access this page.', 'danger')
        return redirect(url_for('login'))

@app.route('/feedback/<int:feedback_id>/delete', methods=['POST'])
def delete_feedback(feedback_id):
    feedback = Feedback.query.get_or_404(feedback_id)
    if 'username' in session and (session['username'] == feedback.user.username or User.query.filter_by(username=session['username'], is_admin=True).first()):
        print("User can delete feedback.")
        db.session.delete(feedback)
        db.session.commit()
        flash('Feedback deleted successfully!', 'success')
    else:
        print("User does not have permission to delete feedback.")
        flash('You do not have permission to delete this feedback.', 'danger')
    return redirect(url_for('user_profile', username=session['username']))

@app.route('/users/<username>/delete', methods=['GET', 'POST'])
def delete_user(username):
    if 'username' in session and (session['username'] == username or User.query.filter_by(username=session['username'], is_admin=True).first()):
        user = User.query.filter_by(username=username).first()
        if user:
            if request.method == 'POST':
                # Delete all user feedbacks before deleting the user
                Feedback.query.filter_by(user_id=user.id).delete()
                db.session.delete(user)
                db.session.commit()
                session.clear()
                flash('User and all associated feedbacks deleted successfully!', 'success')
                return redirect(url_for('login'))

            return render_template('delete_user.html', user=user)

    flash('You do not have permission to access this page.', 'danger')
    return redirect(url_for('login'))

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(401)
def unauthorized(e):
    return render_template('401.html'), 401






