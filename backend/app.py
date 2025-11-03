
# backend/app.py
import os
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime
from sqlalchemy.exc import IntegrityError
from backend.plagiarism import check_similarity_texts
import secrets, csv
from werkzeug.security import generate_password_hash

UPLOAD_FOLDER = os.environ.get("UPLOAD_FOLDER", "uploads")
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'docx'}

PASSWORD_MIN = 8
PASSWORD_MAX = 24

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

app = Flask(
    __name__,
    static_folder=os.path.join(BASE_DIR, '../frontend/static'),
    template_folder=os.path.join(BASE_DIR, '../frontend/templates')
)

app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'change-this-secret')
db_path = os.environ.get('DATABASE_URL', 'sqlite:///student_project_tracker.db')
app.config['SQLALCHEMY_DATABASE_URI'] = db_path
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = os.path.join(BASE_DIR, 'uploads')
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Models
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    email = db.Column(db.String(150),unique=True, nullable=True)
    role = db.Column(db.String(50), default='student')  # 'teacher' or 'student'
    is_temp_password = db.Column(db.Boolean, default=False)  # 👈 NEW FIELD


class Student(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)  # link to account
    name = db.Column(db.String(150))
    student_class = db.Column(db.String(100))
    email = db.Column(db.String(150),unique=True, nullable=True)


class Assignment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(300))
    filename = db.Column(db.String(300))
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow)
    uploader_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    type = db.Column(db.String(20), default='question')  # 'question' or 'answer'
    parent_id = db.Column(db.Integer, db.ForeignKey('assignment.id'), nullable=True)
    
class Feedback(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    teacher_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    answer_id = db.Column(db.Integer, db.ForeignKey('assignment.id'), nullable=False)  # link to answer (Assignment.type='answer')
    comments = db.Column(db.Text, nullable=True)
    rating = db.Column(db.Integer, nullable=True)  # optional numeric rating (1-5)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Notification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    message = db.Column(db.String(300), nullable=False)
    is_read = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

def create_notification(user_id, message):
    note = Notification(user_id=user_id, message=message)
    db.session.add(note)
    db.session.commit()



@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def teacher_required(fn):
    from functools import wraps
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'teacher':
            flash('Teacher access required', 'danger')
            return redirect(url_for('dashboard'))
        return fn(*args, **kwargs)
    return wrapper

# Routes
@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return render_template('home.html')

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']
        role = request.form.get('role', 'student')
        email = request.form.get('email', '').strip()
        sclass = request.form.get('student_class', '').strip()

        # Validate username and password
        if not username or not password:
            flash('Username and password are required.', 'danger')
            return redirect(url_for('register'))

        # ✅ Password length validation
        if len(password) < PASSWORD_MIN or len(password) > PASSWORD_MAX:
            flash(f'Password must be between {PASSWORD_MIN} and {PASSWORD_MAX} characters.', 'danger')
            return redirect(url_for('register'))

        # Check if username or email already exists
        if User.query.filter_by(username=username).first():
            flash('Username already exists.', 'danger')
            return redirect(url_for('register'))
        if email and User.query.filter_by(email=email).first():
            flash('Email already registered.', 'danger')
            return redirect(url_for('register'))

        # Hash and create user
        hashed = generate_password_hash(password, method='sha256')
        user = User(username=username, password=hashed, role=role, email=email)
        db.session.add(user)
        db.session.commit()

        # If student, add entry in Student table
        if role == 'student':
            st = Student(name=username, student_class=sclass, email=email, user_id=user.id)
            db.session.add(st)
            db.session.commit()

        flash('Registration successful! You can now log in.', 'success')
        return redirect(url_for('login'))
        
    return render_template('register.html')


from werkzeug.security import check_password_hash

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password, password):
            login_user(user)
            if user.role == 'student' and user.is_temp_password:
                flash('Please change your temporary password before proceeding.', 'warning')
                return redirect(url_for('change_password'))
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid credentials', 'danger')
    return render_template('login.html')

@app.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    if request.method == 'POST':
        new_pw = request.form['new_password']
        confirm_pw = request.form['confirm_password']
        if new_pw != confirm_pw:
            flash('Passwords do not match.', 'danger')
            return redirect(url_for('change_password'))
        if len(new_pw) < PASSWORD_MIN or len(new_pw) > PASSWORD_MAX:
            flash(f'Password must be between {PASSWORD_MIN} and {PASSWORD_MAX} characters.', 'danger')
            return redirect(url_for('change_password'))

        current_user.password = generate_password_hash(new_pw, method='sha256')
        current_user.is_temp_password = False
        db.session.commit()
        flash('Password updated successfully!', 'success')
        return redirect(url_for('dashboard'))
    return render_template('change_password.html')



@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out', 'info')
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    # Fetch notifications for logged-in user
    notifications = Notification.query.filter_by(user_id=current_user.id)\
        .order_by(Notification.created_at.desc()).limit(5).all()
    notif_count = Notification.query.filter_by(user_id=current_user.id, is_read=False).count()

    # --- TEACHER DASHBOARD ---
    if current_user.role == 'teacher':
        total_students = Student.query.count()
        total_questions = Assignment.query.filter_by(type='question').count()
        total_answers = Assignment.query.filter_by(type='answer').count()
        questions = Assignment.query.filter_by(type='question').order_by(Assignment.uploaded_at.desc()).all()
        students = Student.query.all()

        return render_template(
            'dashboard_teacher.html',
            total_students=total_students,
            total_questions=total_questions,
            total_answers=total_answers,
            questions=questions,
            students=students,
            notifications=notifications,
            notif_count=notif_count
        )

    # --- STUDENT DASHBOARD ---
    else:
        # Get all questions (assignments of type 'question')
        questions = Assignment.query.filter_by(type='question').all()
        
        # Get all answers uploaded by this student
        my_answers = Assignment.query.filter_by(type='answer', uploader_id=current_user.id).all()

        # Get all feedbacks for this student's answers
        answer_ids = [a.id for a in my_answers]
        fb_map = {}
        if answer_ids:
            all_feedbacks = Feedback.query.filter(Feedback.answer_id.in_(answer_ids)).all()
            for fb in all_feedbacks:
                fb_map.setdefault(fb.answer_id, []).append(fb)

        # Render student dashboard
        return render_template(
            'dashboard_student.html',
            questions=questions,
            my_answers=my_answers,
            feedbacks=fb_map,        # ✅ Restored variable
            notifications=notifications,
            notif_count=notif_count
        )

@app.route('/api/analytics')
@login_required
@teacher_required
def analytics_data():
    # Count total submissions and feedbacks per student
    students = Student.query.all()
    labels = []
    submissions = []
    feedbacks = []

    for s in students:
        labels.append(s.name)
        subs = Assignment.query.filter_by(uploader_id=s.user_id, type='answer').count()
        feeds = Feedback.query.join(Assignment, Feedback.answer_id == Assignment.id)\
            .filter(Assignment.uploader_id == s.user_id).count()
        submissions.append(subs)
        feedbacks.append(feeds)

    return jsonify({
        'labels': labels,
        'submissions': submissions,
        'feedbacks': feedbacks
    })

@app.route('/students/add', methods=['GET', 'POST'])
@login_required
@teacher_required
def add_student():
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        email = request.form.get('email', '').strip()
        sclass = request.form.get('class_name', '').strip()

        # Basic validation
        if not name or not username:
            flash('Name and username are required', 'danger')
            return redirect(url_for('add_student'))

        # Password length validation if provided; if blank we auto-generate (temp)
        is_temp = False
        if password:
            if len(password) < PASSWORD_MIN or len(password) > PASSWORD_MAX:
                flash(f'Password must be between {PASSWORD_MIN} and {PASSWORD_MAX} characters.', 'danger')
                return redirect(url_for('add_student'))
        else:
            password = secrets.token_urlsafe(8)
            is_temp = True

        # Check uniqueness: username and email
        if User.query.filter_by(username=username).first():
            flash('Username already exists — choose another', 'danger')
            return redirect(url_for('add_student'))
        if email and User.query.filter_by(email=email).first():
            flash('Email already used by another account — use a different email', 'danger')
            return redirect(url_for('add_student'))
        if email and Student.query.filter_by(email=email).first():
            flash('Email already used by another student — cannot add duplicate', 'danger')
            return redirect(url_for('add_student'))

        # Create user
        hashed_pw = generate_password_hash(password, method='sha256')
        new_user = User(username=username, password=hashed_pw, role='student', email=email, is_temp_password=is_temp)
        db.session.add(new_user)
        try:
            db.session.commit()
        except IntegrityError:
            db.session.rollback()
            flash('User creation failed (duplicate).', 'danger')
            return redirect(url_for('add_student'))

        # Create student
        new_student = Student(user_id=new_user.id, name=name, student_class=sclass, email=email)
        db.session.add(new_student)
        try:
            db.session.commit()
        except IntegrityError:
            db.session.rollback()
            # rollback also remove user to avoid orphans if desired
            db.session.delete(new_user)
            db.session.commit()
            flash('Student creation failed (duplicate email).', 'danger')
            return redirect(url_for('add_student'))

        # Append to CSV credentials (teacher record)
        csv_path = os.path.join(os.getcwd(), "student_credentials.csv")
        file_exists = os.path.isfile(csv_path)
        with open(csv_path, "a", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            if not file_exists:
                writer.writerow(["Name", "Username", "Password", "Class", "Email"])
            writer.writerow([name, username, password, sclass, email])

        flash(f'Student "{name}" added. Username: {username} | Password: {password}', 'success')
        return redirect(url_for('dashboard'))

    return render_template('add_student.html')

@app.route('/students/delete/<int:sid>', methods=['POST'])
@login_required
@teacher_required
def delete_student(sid):
    st = Student.query.get_or_404(sid)
    # delete linked user if exists
    if st.user_id:
        u = User.query.get(st.user_id)
        if u:
            db.session.delete(u)
    db.session.delete(st)
    db.session.commit()
    flash('Student and linked user account deleted', 'info')
    return redirect(url_for('dashboard'))

from flask import send_file

@app.route('/download/students')
@login_required
@teacher_required
def download_students():
    csv_path = os.path.join(os.getcwd(), "student_credentials.csv")
    if not os.path.exists(csv_path):
        flash('No student credentials file found yet.', 'warning')
        return redirect(url_for('dashboard'))
    return send_file(csv_path, as_attachment=True)


@app.route('/assignments/upload_question', methods=['GET', 'POST'])
@login_required
@teacher_required
def upload_question():
    if request.method == 'POST':
        title = request.form.get('title') or 'Untitled Question'
        if 'file' not in request.files:
            flash('No file part', 'danger')
            return redirect(request.url)
        file = request.files['file']
        if file.filename == '':
            flash('No selected file', 'danger')
            return redirect(request.url)
        if file and allowed_file(file.filename):
            fname = secure_filename(f"q_{int(datetime.utcnow().timestamp())}_{file.filename}")
            os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
            path = os.path.join(app.config['UPLOAD_FOLDER'], fname)
            file.save(path)
            a = Assignment(title=title, filename=fname, uploader_id=current_user.id, type='question')
            db.session.add(a)
            db.session.commit()
            # Notify all students
            students = User.query.filter_by(role='student').all()
            for s in students:
                create_notification(s.id, f"New assignment uploaded: {title}")

            flash('Question uploaded', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('File type not allowed', 'danger')
            return redirect(request.url)
    return render_template('upload_question.html')

@app.route('/assignments/upload_answer/<int:question_id>', methods=['GET', 'POST'])
@login_required
def upload_answer(question_id):
    question = Assignment.query.get_or_404(question_id)
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file part', 'danger')
            return redirect(request.url)
        file = request.files['file']
        if file.filename == '':
            flash('No selected file', 'danger')
            return redirect(request.url)
        if file and allowed_file(file.filename):
            fname = secure_filename(f"a_{int(datetime.utcnow().timestamp())}_{file.filename}")
            os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
            path = os.path.join(app.config['UPLOAD_FOLDER'], fname)
            file.save(path)
            a = Assignment(title=f"Answer to {question.title}", filename=fname, uploader_id=current_user.id, type='answer', parent_id=question.id)
            db.session.add(a)
            db.session.commit()
            # Notify teacher(s)
            teachers = User.query.filter_by(role='teacher').all()
            for t in teachers:
                create_notification(t.id, f"New submission from {current_user.username} for '{question.title}'")

            # Notify student themself (confirmation)
            create_notification(current_user.id, f"You successfully submitted your answer for '{question.title}'")

            similarities = []
            if fname.lower().endswith('.txt'):
                with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                    new_text = f.read()
                others = Assignment.query.filter_by(type='answer', parent_id=question.id).filter(Assignment.id != a.id).all()
                for other in others:
                    otherpath = os.path.join(app.config['UPLOAD_FOLDER'], other.filename)
                    if os.path.exists(otherpath) and otherpath.lower().endswith('.txt'):
                        with open(otherpath, 'r', encoding='utf-8', errors='ignore') as of:
                            other_text = of.read()
                        score = check_similarity_texts(new_text, other_text)
                        if score > 0.75:
                            similarities.append((other.filename, round(score,2)))
            flash('Answer uploaded. Similarities: ' + (str(similarities) if similarities else 'None'), 'info')
            return redirect(url_for('dashboard'))
        else:
            flash('File type not allowed', 'danger')
            return redirect(request.url)
    return render_template('upload_answer.html', question=question)

@app.route('/assignments/view_submissions/<int:question_id>')
@login_required
@teacher_required
def view_submissions(question_id):
    question = Assignment.query.get_or_404(question_id)
    answers = Assignment.query.filter_by(type='answer', parent_id=question_id).all()
    users = {u.id: u.username for u in User.query.all()}

    #  Submission Tracking - calculate how many students have submitted
    total_students = Student.query.count()
    submitted_user_ids = {a.uploader_id for a in answers}
    submitted_count = len(submitted_user_ids)
    pending_count = total_students - submitted_count

    #  Recalculate plagiarism scores (for .txt answers only)
    plagiarism_scores = {}
    for a1 in answers:
        if not a1.filename.lower().endswith('.txt'):
            continue
        path1 = os.path.join(app.config['UPLOAD_FOLDER'], a1.filename)
        if not os.path.exists(path1):
            continue

        with open(path1, 'r', encoding='utf-8', errors='ignore') as f1:
            text1 = f1.read()

        for a2 in answers:
            if a1.id == a2.id or not a2.filename.lower().endswith('.txt'):
                continue
            path2 = os.path.join(app.config['UPLOAD_FOLDER'], a2.filename)
            if not os.path.exists(path2):
                continue

            with open(path2, 'r', encoding='utf-8', errors='ignore') as f2:
                text2 = f2.read()

            score = check_similarity_texts(text1, text2)
            if score > 0.6:  # only show moderate/high similarities
                plagiarism_scores.setdefault(a1.id, []).append((a2.filename, score))

    #  Fetch feedbacks for this question’s answers (for current teacher)
    feedbacks = {
        fb.answer_id: fb
        for fb in Feedback.query.filter(
            Feedback.answer_id.in_([a.id for a in answers]),
            Feedback.teacher_id == current_user.id
        ).all()
    }

    # Calculate tracking stats
    total_feedback_given = len(feedbacks)
    pending_feedback = submitted_count - total_feedback_given

    # Pass tracking summary to template
    return render_template(
        'view_submissions.html',
        question=question,
        answers=answers,
        users=users,
        feedbacks=feedbacks,
        plagiarism_scores=plagiarism_scores,
        total_students=total_students,
        submitted_count=submitted_count,
        pending_count=pending_count,
        total_feedback_given=total_feedback_given,
        pending_feedback=pending_feedback
    )


@app.route('/uploads/<path:filename>')
@login_required
def uploaded_file(filename):
    """Serve uploaded files for download"""
    # Correct path — uploads folder is now inside backend/
    upload_dir = os.path.join(os.path.dirname(__file__), "uploads")

    file_path = os.path.join(upload_dir, filename)
    if not os.path.exists(file_path):
        flash("File not found on server.", "danger")
        return redirect(url_for("dashboard"))

    # Serve file as attachment (force download)
    return send_from_directory(upload_dir, filename, as_attachment=True)



@app.route('/feedback/add/<int:answer_id>', methods=['GET', 'POST'])
@login_required
@teacher_required
def add_feedback(answer_id):
    # Get the student's answer entry
    answer = Assignment.query.get_or_404(answer_id)

    # Ensure this assignment is actually an "answer"
    if answer.type != 'answer':
        flash('Feedback can only be added to student answers.', 'danger')
        return redirect(url_for('dashboard'))

    # Get uploader info (student)
    answer_uploader = User.query.get(answer.uploader_id)

    # Check for existing feedback from this teacher for the same answer
    existing = Feedback.query.filter_by(
        answer_id=answer_id,
        teacher_id=current_user.id
    ).first()

    if request.method == 'POST':
        comments = request.form.get('comments', '').strip()
        rating = request.form.get('rating', '').strip()

        # Validate rating
        try:
            rating_val = int(rating)
            if rating_val < 1 or rating_val > 5:
                raise ValueError
        except ValueError:
            flash('Rating must be an integer between 1 and 5.', 'danger')
            return redirect(url_for('add_feedback', answer_id=answer_id))

        # Create new feedback or update existing
        if existing:
            existing.comments = comments
            existing.rating = rating_val
            existing.created_at = datetime.utcnow()
            flash('Feedback updated successfully.', 'success')
        else:
            new_feedback = Feedback(
                teacher_id=current_user.id,
                answer_id=answer_id,
                comments=comments,
                rating=rating_val
            )
            db.session.add(new_feedback)
            flash('Feedback added successfully.', 'success')

        db.session.commit()
        # Notify student of feedback
        student_answer = Assignment.query.get(answer_id)
        if student_answer:
            create_notification(student_answer.uploader_id, f"Feedback added by {current_user.username} on '{student_answer.title}'")

        return redirect(url_for('view_submissions', question_id=answer.parent_id))

    # GET request — render the feedback form
    return render_template(
        'add_feedback.html',
        answer=answer,
        existing=existing,
        answer_uploader=answer_uploader
        )

@app.context_processor
def inject_notifications():
    if current_user.is_authenticated:
        notes = Notification.query.filter_by(user_id=current_user.id).order_by(Notification.created_at.desc()).limit(5).all()
        unread_count = Notification.query.filter_by(user_id=current_user.id, is_read=False).count()
        return dict(notifications=notes, notif_count=unread_count)
    return dict(notifications=None, notif_count=0)


def seed_data():
    if User.query.count() == 0:
        t = User(username='teacher1', password=generate_password_hash('teacherpass', method='sha256'), role='teacher', email='teacher@example.com')
        s = User(username='student1', password=generate_password_hash('studentpass', method='sha256'), role='student', email='student@example.com')
        db.session.add_all([t,s])
        st1 = Student(name='Alice Kumar', student_class='10th', email='alice@example.com')
        st2 = Student(name='Rahul Singh', student_class='12th', email='rahul@example.com')
        db.session.add_all([st1, st2])
        os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
        with open(os.path.join(app.config['UPLOAD_FOLDER'], 'q_sample1.txt'), 'w') as f:
            f.write('Sample question: Write an essay on wireless communications.')
        q = Assignment(title='Wireless Essay', filename='q_sample1.txt', uploader_id=1, type='question')
        db.session.add(q)
        db.session.commit()

def create_app():
    with app.app_context():
        db.create_all()
        seed_data()
    return app

if __name__ == '__main__':
    create_app()
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT',8000)), debug=False)
