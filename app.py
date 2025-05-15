import os
from flask import Flask, render_template, redirect, url_for, session, flash, request
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField
from wtforms.validators import DataRequired

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'your_very_secret_key_replace_in_production')
application = app

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login' 
login_manager.login_message = "Для доступа к этой странице необходимо войти."
login_manager.login_message_category = "info"

users_db = {
    "admin": {
        "password": "12345",
        "id": "admin"
    }
}

class User(UserMixin):
    def __init__(self, id):
        self.id = id

@login_manager.user_loader
def load_user(user_id):
    if user_id in users_db:
        return User(user_id)
    return None

class LoginForm(FlaskForm):
    username = StringField('Логин', validators=[DataRequired(message="Поле не может быть пустым")])
    password = PasswordField('Пароль', validators=[DataRequired(message="Пароль не может быть пустым")])
    remember_me = BooleanField('Запомнить меня')
    submit = SubmitField('Войти')

@app.route('/')
def index():
    """Главная страница."""
    return render_template('index.html')

@app.route('/visits')
def visits():
    """Страница счетчика посещений."""
    if 'visits' not in session:
        session['visits'] = 0
    session['visits'] += 1
    count = session['visits']
    return render_template('visits.html', visits=count)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        remember = form.remember_me.data

        user_data = users_db.get(username)

        if user_data and user_data['password'] == password:
            user = User(username)
            login_user(user, remember=remember)
            flash('Вы успешно вошли!', 'success')

            next_page = request.args.get('next')
            if not next_page or not next_page.startswith('/'):
                 next_page = url_for('index')
            return redirect(next_page)
        else:
            flash('Неверный логин или пароль.', 'danger')

    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    """Выход пользователя."""
    logout_user()
    flash('Вы вышли из системы.', 'info')
    return redirect(url_for('index'))

@app.route('/secret')
@login_required
def secret():
    """Секретная страница."""
    return render_template('secret.html')

if __name__ == '__main__':
    app.run(debug=True)