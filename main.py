from flask import Flask, render_template, request, redirect, url_for, send_from_directory, session
from flask_session import Session
from datetime import timedelta, datetime
import os
from PIL import Image
import hashlib
import jwt  # Izmantojam pyjwt bibliotēku
from database import init_db, get_user, add_user

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'uploads'
app.secret_key = 'tava_slepenā_atslēga'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=30)  # Sesijas derīguma termiņš - 30 dienas
app.config['SESSION_TYPE'] = 'filesystem'  # Izmantojam failu sistēmu sesiju glabāšanai
MAX_FILE_SIZE = 2 * 1024 * 1024
MAX_IMAGE_DIMENSIONS = (1000, 1000)
DEFAULT_AVATAR_FILENAME = 'avatar.png'  # Noklusējuma avatara faila nosaukums
DEFAULT_AVATAR_PATH = os.path.join('static', 'images', DEFAULT_AVATAR_FILENAME)

if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

Session(app)

def get_next_image_number():
    files = os.listdir(app.config['UPLOAD_FOLDER'])
    image_numbers = [int(file.split('.')[0]) for file in files if file.split('.')[0].isdigit()]
    if image_numbers:
        return max(image_numbers) + 1
    else:
        return 1

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def check_password(hashed_password, user_password):
    return hashed_password == hashlib.sha256(user_password.encode()).hexdigest()

def generate_token(username):
    payload = {
        'username': username,
        'exp': datetime.utcnow() + timedelta(days=30)  # Token derīgs 30 dienas
    }
    token = jwt.encode(payload, app.secret_key, algorithm='HS256')
    return token

def verify_token(token):
    try:
        payload = jwt.decode(token, app.secret_key, algorithms=['HS256'])
        return payload['username']
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

@app.before_request
def make_session_permanent():
    session.permanent = True
    session.modified = True
    if 'username' not in session and request.endpoint not in ('login', 'register', 'index', 'static', 'uploaded_file', 'contact'):
        return redirect(url_for('index'))

def ensure_default_avatar():
    next_image_number = get_next_image_number()
    default_avatar_target_path = os.path.join(app.config['UPLOAD_FOLDER'], f"{next_image_number}.png")
    if not os.path.exists(default_avatar_target_path):
        if os.path.exists(DEFAULT_AVATAR_PATH):
            from shutil import copyfile
            copyfile(DEFAULT_AVATAR_PATH, default_avatar_target_path)
        else:
            print("Default avatar not found in static/images directory.")

@app.route('/')
def index():
    message = request.args.get('message')
    return render_template('index.html', message=message)

@app.route('/login', methods=['GET', 'POST'])
def login():
    message = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = get_user(username)
        if user and check_password(user['password'], password):
            session['username'] = user['username']
            token = generate_token(username)
            response = redirect(url_for('index'))
            response.set_cookie('token', token, httponly=True)
            return response
        else:
            message = "Nepareizs lietotājvārds vai parole. Lūdzu, mēģiniet vēlreiz."
    return render_template('login.html', message=message)

@app.route('/register', methods=['GET', 'POST'])
def register():
    message = request.args.get('message')
    if request.method == 'POST':
        username = request.form['username']
        password = hash_password(request.form['password'])
        first_name = request.form['first_name']
        last_name = request.form['last_name']
        email = request.form['email']
        photo = request.files['photo']

        existing_user = get_user(username)
        if existing_user:
            message = 'Lietotājvārds jau eksistē. Lūdzu, izvēlieties citu lietotājvārdu.'
            return redirect(url_for('register', message=message))

        if photo and photo.filename != '':
            # Pārbauda faila veidu
            allowed_extensions = {'image/jpeg', 'image/png'}
            if photo.content_type not in allowed_extensions:
                message = 'Lūdzu, augšupielādējiet tikai attēlu failus (JPG vai PNG).'
                return redirect(url_for('register', message=message))

            # Pārbauda faila izmēru
            if photo.content_length > MAX_FILE_SIZE:
                message = 'Faila izmērs ir pārāk liels. Maksimālais izmērs ir 2 MB.'
                return redirect(url_for('register', message=message))

            # Pārbauda attēla izmērus
            try:
                image = Image.open(photo)
                image.verify()  # Verificē, ka fails tiešām ir attēls un nav bojāts

                if image.size[0] > MAX_IMAGE_DIMENSIONS[0] or image.size[1] > MAX_IMAGE_DIMENSIONS[1]:
                    message = 'Attēla izšķirtspēja ir pārāk liela. Maksimālā izšķirtspēja ir 1000x1000 pikseļi.'
                    return redirect(url_for('register', message=message))

                # Pārlādē attēlu pēc verifikācijas
                photo.seek(0)
                image = Image.open(photo)

                next_image_number = get_next_image_number()
                photo_extension = 'png' if photo.content_type == 'image/png' else 'jpg'
                photo_filename = f"{next_image_number}.{photo_extension}"
                photo_path = os.path.join(app.config['UPLOAD_FOLDER'], photo_filename)
                image.save(photo_path)  # Saglabā attēlu, izmantojot PIL

                # Saglabā relatīvo ceļu datu bāzē, nevis pilnu ceļu
                photo_url = photo_filename
            except (IOError, SyntaxError) as e:
                message = 'Augšupielādētais fails nav derīgs attēls vai ir bojāts.'
                return redirect(url_for('register', message=message))
        else:
            # Izmanto noklusējuma attēlu, ja neaugšupielādēts neviens attēls
            next_image_number = get_next_image_number()
            photo_url = f"{next_image_number}.png"
            default_avatar_source = os.path.join(app.static_folder, 'images', DEFAULT_AVATAR_FILENAME)
            default_avatar_target = os.path.join(app.config['UPLOAD_FOLDER'], photo_url)
            from shutil import copyfile
            copyfile(default_avatar_source, default_avatar_target)

        add_user(username, password, first_name, last_name, email, photo_url)
        return redirect(url_for('login'))

    return render_template('register.html', message=message)

@app.route('/profile')
def profile():
    if 'username' in session:
        user = get_user(session['username'])
        return render_template('profile.html', user=user)
    return redirect(url_for('login'))

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/logout')
def logout():
    session.pop('username', None)
    response = redirect(url_for('index'))
    response.delete_cookie('token')
    return response

@app.route('/contact')
def contact():
    return render_template('contact.html')

if __name__ == '__main__':
    init_db()
    ensure_default_avatar()  # Pārliecinieties, ka noklusējuma avatara fails tiek kopēts augšupielādēs
    app.run(debug=True)
