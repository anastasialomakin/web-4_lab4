import os
import re
from datetime import datetime
from flask import Flask, render_template, redirect, url_for, session, flash, request
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate 
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField, SelectField
from wtforms.validators import DataRequired, Length, EqualTo, Regexp, ValidationError
from werkzeug.security import generate_password_hash, check_password_hash

# конфига
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'your_very_secret_key_replace_in_production_for_real')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///site.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
application = app 

# инициализация бд
db = SQLAlchemy(app)
migrate = Migrate(app, db) 

# менеджер логинов
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = "Для доступа к этой странице необходимо войти."
login_manager.login_message_category = "info"

# бд
class Role(db.Model):
    __tablename__ = 'roles'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), unique=True, nullable=False)
    description = db.Column(db.String(255))
    users = db.relationship('User', backref='role', lazy='dynamic')

    def __repr__(self):
        return f'<Role {self.name}>'

class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    first_name = db.Column(db.String(100), nullable=False)
    last_name = db.Column(db.String(100), nullable=True) # Фамилия может отсутствовать
    middle_name = db.Column(db.String(100), nullable=True) # Отчество может отсутствовать
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    role_id = db.Column(db.Integer, db.ForeignKey('roles.id'), nullable=True) # Роль может отсутствовать

    def __init__(self, username, first_name, last_name=None, middle_name=None, role_id=None):
        self.username = username
        self.first_name = first_name
        self.last_name = last_name
        self.middle_name = middle_name
        self.role_id = role_id

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def get_fio(self):
        parts = [self.last_name, self.first_name, self.middle_name]
        return " ".join(p for p in parts if p) or self.username 

    def __repr__(self):
        return f'<User {self.username}>'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# валидатор
def password_complexity_validator(form, field):
    password = field.data
    errors = []
    if not re.search(r"[A-ZА-Я]", password):
        errors.append("Пароль должен содержать хотя бы одну заглавную букву.")
    if not re.search(r"[a-zа-я]", password):
        errors.append("Пароль должен содержать хотя бы одну строчную букву.")
    if not re.search(r"\d", password):
        errors.append("Пароль должен содержать хотя бы одну арабскую цифру.")
    if re.search(r"\s", password):
        errors.append("Пароль не должен содержать пробелов.")
    
    allowed_chars_pattern = r"^[a-zA-Zа-яА-Я0-9~!?@#$%^&*_\-+=()[\]{}><\/\\|\"'.,:;]*$"
    if not re.match(allowed_chars_pattern, password):
        errors.append("Пароль содержит недопустимые символы.")
    
    if errors:
        raise ValidationError(" ".join(errors))


# формы
class LoginForm(FlaskForm):
    username = StringField('Логин', validators=[DataRequired(message="Поле не может быть пустым")])
    password = PasswordField('Пароль', validators=[DataRequired(message="Пароль не может быть пустым")])
    remember_me = BooleanField('Запомнить меня')
    submit = SubmitField('Войти')

class UserForm(FlaskForm):
    username = StringField('Логин', validators=[
        DataRequired(message="Поле 'Логин' не может быть пустым."),
        Length(min=5, message="Логин должен быть не менее 5 символов."),
        Regexp(r'^[a-zA-Z0-9]+$', message="Логин должен состоять только из латинских букв и цифр.")
    ])
    password = PasswordField('Пароль', validators=[
        DataRequired(message="Поле 'Пароль' не может быть пустым."),
        Length(min=8, max=128, message="Пароль должен быть от 8 до 128 символов."),
        password_complexity_validator
    ])
    first_name = StringField('Имя', validators=[DataRequired(message="Поле 'Имя' не может быть пустым.")])
    last_name = StringField('Фамилия') 
    middle_name = StringField('Отчество') 
    role = SelectField('Роль', coerce=int, validate_choice=False) 
    submit = SubmitField('Сохранить')

    def __init__(self, *args, **kwargs):
        super(UserForm, self).__init__(*args, **kwargs)
        self.role.choices = [(0, '--- Без роли ---')] + [(role.id, role.name) for role in Role.query.order_by('name').all()]

class UserEditForm(FlaskForm):
    first_name = StringField('Имя', validators=[DataRequired(message="Поле 'Имя' не может быть пустым.")])
    last_name = StringField('Фамилия')
    middle_name = StringField('Отчество')
    role = SelectField('Роль', coerce=int, validate_choice=False)
    submit = SubmitField('Сохранить изменения')

    def __init__(self, *args, **kwargs):
        super(UserEditForm, self).__init__(*args, **kwargs)
        self.role.choices = [(0, '--- Без роли ---')] + [(role.id, role.name) for role in Role.query.order_by('name').all()]

class ChangePasswordForm(FlaskForm):
    old_password = PasswordField('Старый пароль', validators=[DataRequired(message="Это поле обязательно.")])
    new_password = PasswordField('Новый пароль', validators=[
        DataRequired(message="Это поле обязательно."),
        Length(min=8, max=128, message="Пароль должен быть от 8 до 128 символов."),
        password_complexity_validator
    ])
    confirm_new_password = PasswordField('Повторите новый пароль', validators=[
        DataRequired(message="Это поле обязательно."),
        EqualTo('new_password', message='Пароли должны совпадать.')
    ])
    submit = SubmitField('Изменить пароль')

class DeleteUserForm(FlaskForm):
    submit = SubmitField('Да, удалить')

# декортаторы
@app.route('/')
def index():
    """Главная страница - список пользователей."""
    users = User.query.order_by(User.created_at.desc()).all()
    delete_form = DeleteUserForm() 
    return render_template('index.html', users=users, delete_form=delete_form)

@app.route('/visits')
def visits():
    """Страница счетчика посещений."""
    session['visits'] = session.get('visits', 0) + 1
    return render_template('visits.html', visits=session['visits'])

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and user.check_password(form.password.data):
            login_user(user, remember=form.remember_me.data)
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
    logout_user()
    flash('Вы вышли из системы.', 'info')
    return redirect(url_for('index'))

@app.route('/secret')
@login_required
def secret():
    return render_template('secret.html')

# CRUD
@app.route('/users/new', methods=['GET', 'POST'])
@login_required
def create_user():
    form = UserForm()
    if form.validate_on_submit():
        try:
            existing_user = User.query.filter_by(username=form.username.data).first()
            if existing_user:
                form.username.errors.append("Пользователь с таким логином уже существует.")
                flash('Ошибка при создании пользователя. Проверьте данные.', 'danger')
                return render_template('user_form_page.html', form=form, title="Создание пользователя", is_edit=False)

            new_user = User(
                username=form.username.data,
                first_name=form.first_name.data,
                last_name=form.last_name.data or None, 
                middle_name=form.middle_name.data or None,
                role_id=form.role.data if form.role.data != 0 else None # 0 - без роли
            )
            new_user.set_password(form.password.data)
            db.session.add(new_user)
            db.session.commit()
            flash(f'Пользователь {new_user.username} успешно создан!', 'success')
            return redirect(url_for('index'))
        except Exception as e:
            db.session.rollback()
            flash(f'Ошибка при создании пользователя: {str(e)}', 'danger')
    elif request.method == 'POST':
        flash('Ошибка при создании пользователя. Проверьте введенные данные.', 'danger')

    return render_template('user_form_page.html', form=form, title="Создание пользователя", is_edit=False)


@app.route('/users/<int:user_id>/view')
def view_user(user_id):
    user = User.query.get_or_404(user_id)
    return render_template('user_view.html', user=user)

@app.route('/users/<int:user_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_user(user_id):
    user_to_edit = User.query.get_or_404(user_id)
    form = UserEditForm(obj=user_to_edit) 

    if request.method == 'GET':
        form.role.data = user_to_edit.role_id if user_to_edit.role_id else 0

    if form.validate_on_submit():
        try:
            user_to_edit.first_name = form.first_name.data
            user_to_edit.last_name = form.last_name.data or None
            user_to_edit.middle_name = form.middle_name.data or None
            user_to_edit.role_id = form.role.data if form.role.data != 0 else None
            db.session.commit()
            flash(f'Данные пользователя {user_to_edit.username} успешно обновлены!', 'success')
            return redirect(url_for('index'))
        except Exception as e:
            db.session.rollback()
            flash(f'Ошибка при обновлении пользователя: {str(e)}', 'danger')
    elif request.method == 'POST': 
         flash('Ошибка при обновлении пользователя. Проверьте введенные данные.', 'danger')

    return render_template('user_form_page.html', form=form, title=f"Редактирование: {user_to_edit.get_fio()}", user=user_to_edit, is_edit=True)


@app.route('/users/<int:user_id>/delete', methods=['POST'])
@login_required
def delete_user(user_id):
    user_to_delete = User.query.get_or_404(user_id)
    if user_to_delete == current_user: 
        flash('Вы не можете удалить свою учетную запись.', 'warning')
        return redirect(url_for('index'))
    try:
        fio = user_to_delete.get_fio()
        db.session.delete(user_to_delete)
        db.session.commit()
        flash(f'Пользователь {fio} успешно удален.', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Ошибка при удалении пользователя: {str(e)}', 'danger')
    return redirect(url_for('index'))

@app.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    form = ChangePasswordForm()
    if form.validate_on_submit():
        if current_user.check_password(form.old_password.data):
            try:
                current_user.set_password(form.new_password.data)
                db.session.commit()
                flash('Пароль успешно изменен.', 'success')
                return redirect(url_for('index'))
            except Exception as e:
                db.session.rollback()
                flash(f'Ошибка при смене пароля: {str(e)}', 'danger')
        else:
            form.old_password.errors.append('Неверный старый пароль.')
            flash('Ошибка при смене пароля. Проверьте данные.', 'danger')
    elif request.method == 'POST': 
        flash('Ошибка при смене пароля. Проверьте введенные данные.', 'danger')

    return render_template('change_password.html', form=form, title="Изменение пароля")

# админ вручную
def create_initial_roles_and_admin():
    with app.app_context():
        db.create_all() 

        if Role.query.count() == 0:
            print("Creating initial roles...")
            admin_role = Role(name='Администратор', description='Полный доступ к системе')
            user_role = Role(name='Пользователь', description='Стандартные права пользователя')
            editor_role = Role(name='Редактор', description='Может редактировать контент')
            db.session.add_all([admin_role, user_role, editor_role])
            db.session.commit()
            print("Roles created.")
        else:
            print("Roles already exist.")
            admin_role = Role.query.filter_by(name='Администратор').first()

        if User.query.filter_by(username='admin').first() is None:
            print("Creating admin user...")
            admin_user = User(username='admin', first_name='Админ', role_id=admin_role.id if admin_role else None)
            admin_user.set_password('Admin123!') 
            db.session.add(admin_user)
            db.session.commit()
            print("Admin user created. Login: admin, Password: Admin123!")
        else:
            print("Admin user already exists.")

if __name__ == '__main__':
    create_initial_roles_and_admin() 
    app.run(debug=True)