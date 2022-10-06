from flask import Flask, render_template, session, request, redirect, url_for, flash
from flask_login import LoginManager, UserMixin, current_user, login_user, logout_user, login_required
from mysqldb import MySQL
import mysql.connector as connector
import re

login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.login_message = 'Для доступа к этой странице необходимо пройти процедуру аутентификации'
login_manager.login_message_category = 'warning'

app = Flask(__name__)
application = app

app.config.from_pyfile('config.py')

login_manager.init_app(app)

mysql = MySQL(app)

CREATE_PARAMS = ['login', 'password', 'first_name',
                 'last_name', 'middle_name', 'role_id']

UPDATE_PARAMS = ['first_name', 'last_name', 'middle_name', 'role_id']


def request_params(params_list):
    params = {}

    for param_name in params_list:
        params[param_name] = request.form.get(param_name) or None

    return params


def load_roles():
    with mysql.connection.cursor(named_tuple=True) as cursor:
        cursor.execute('SELECT id, name FROM roles;')
        roles = cursor.fetchall()
    return roles


class User(UserMixin):
    def __init__(self, user_id, login):
        super().__init__()
        self.id = user_id
        self.login = login


@login_manager.user_loader
def load_user(user_id):
    with mysql.connection.cursor(named_tuple=True) as cursor:
        cursor.execute('SELECT * FROM users WHERE id=%s;', (user_id,))
        db_user = cursor.fetchone()
    if db_user:
        return User(user_id=db_user.id, login=db_user.login)
    return None


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        login_ = request.form.get('login')
        password_ = request.form.get('password')
        remember_me_ = request.form.get('remember_me') == 'on'

        with mysql.connection.cursor(named_tuple=True) as cursor:
            cursor.execute(
                'SELECT * FROM users WHERE login=%s and password_hash=SHA2(%s, 256);', (login_, password_))
            db_user = cursor.fetchone()

        if db_user:
            login_user(
                User(user_id=db_user.id, login=db_user.login), remember=remember_me_)

            flash('Вы успешно прошли процедуру аутентификации.', 'success')
            next_ = request.args.get('next')
            return redirect(next_ or url_for('index'))

        flash('Введены неверные логин и/или пароль.', 'danger')

    return render_template('login.html')


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('index'))


@app.route('/users')
def users():

    with mysql.connection.cursor(named_tuple=True) as cursor:
        cursor.execute(
            'SELECT users.*, roles.name AS role_name FROM users LEFT JOIN roles ON users.role_id = roles.id;'
        )
        users = cursor.fetchall()

    return render_template('users/index.html', users=users)


@app.route('/users/new')
@login_required
def new():
    return render_template('users/new.html', errors={'login': None, 'password': None, 'last_name': None, 'first_name': None}, user={}, roles=load_roles())


@app.route('/users/create', methods=['POST'])
@login_required
def create():
    params = request_params(CREATE_PARAMS)
    params['role_id'] = int(params['role_id']) if params['role_id'] else None

    errors = validate_params(params)
    print(errors)

    if errors['login'] is not None or errors['password'] is not None or errors['first_name'] is not None or errors['last_name'] is not None:
        return render_template('users/new.html', user=params, roles=load_roles(), errors=errors)
    
    else:
        with mysql.connection.cursor(named_tuple=True) as cursor:
            try:
                cursor.execute(
                    ('INSERT INTO users (login, password_hash, last_name, first_name, middle_name, role_id)'
                    'VALUES (%(login)s, SHA2(%(password)s, 256), %(last_name)s, %(first_name)s, %(middle_name)s, %(role_id)s);'),
                    params
                )
                mysql.connection.commit()
            except connector.Error:
                flash('Введены некорректные данные. Ошибка сохранения', 'danger')
                return render_template('users/new.html', user=params, roles=load_roles(), errors=errors)
        flash(f"Пользователь {params.get('login')} был успешно создан!", 'success')
        return redirect(url_for('users'))


@app.route('/users/<int:user_id>')
def show(user_id):
    with mysql.connection.cursor(named_tuple=True) as cursor:
        cursor.execute('SELECT * FROM users WHERE id=%s;', (user_id,))
        user = cursor.fetchone()
    return render_template('users/show.html', user=user)


@app.route('/users/<int:user_id>/edit')
@login_required
def edit(user_id):
    with mysql.connection.cursor(named_tuple=True) as cursor:
        cursor.execute('SELECT * FROM users WHERE id=%s;', (user_id,))
        user = cursor.fetchone()
    return render_template('users/edit.html', user=user, errors={'login': None, 'password': None, 'last_name': None, 'first_name': None}, roles=load_roles())


@app.route('/users/<int:user_id>/update', methods=['POST'])
@login_required
def update(user_id):
    params = request_params(UPDATE_PARAMS)
    params['role_id'] = int(params['role_id']) if params['role_id'] else None
    params['id'] = user_id
     
    errors = {'first_name': validate_fio(params['first_name']), 'last_name': validate_fio(params['last_name'])}
    print(errors)

    if errors['first_name'] != 'Ok' or errors['last_name'] is not None:
        return render_template('users/edit.html', user=params, roles=load_roles(), errors=errors)
    
    else:
        with mysql.connection.cursor(named_tuple=True) as cursor:
            try:
                cursor.execute(
                    ('UPDATE users SET last_name=%(last_name)s, first_name=%(first_name)s, middle_name=%(middle_name)s, role_id=%(role_id)s,'
                    'middle_name=%(middle_name)s, role_id=%(role_id)s WHERE id=%(id)s;'), params)
                mysql.connection.commit()
            except connector.Error:
                flash('Введены некорректные данные. Ошибка сохранения', 'danger')
                return render_template('users/edit.html', user=params, roles=load_roles(), errors=errors)
        flash("Пользователь был успешно обновлен!", 'success')
        return redirect(url_for('show', user_id=user_id))


@app.route('/users/<int:user_id>/delete', methods=['POST'])
@login_required
def delete(user_id):
    with mysql.connection.cursor(named_tuple=True) as cursor:
        try:
            cursor.execute(
                ('DELETE FROM users WHERE id=%s'), (user_id, ))
            mysql.connection.commit()
        except connector.Error:
            flash('Не удалось удалить пользователя', 'danger')
            return redirect(url_for('users'))
    flash("Пользователь был успешно удален!", 'success')
    return redirect(url_for('users'))

PASSWORD_PARAMS = ['user_id', 'password_old', 'password_new', 'password_confirm']

@app.route('/users/password', methods=['GET', 'POST'])
@login_required
def password():
    params = request_params(PASSWORD_PARAMS)
    params['user_id'] = current_user.id

    msg = {'password_old': '', 'password_new': '', 'password_confirm': ''}
    validation = {'password_old': '', 'password_new': '', 'password_confirm': ''}
    feedback = {'password_old': '', 'password_new': '', 'password_confirm': ''}

    if params['password_new'] != params['password_confirm']:
        msg['password_new'] = 'Новый пароль и подтверждение пароля не совпадают!'
        msg['password_confirm'] = 'Новый пароль и подтверждение пароля не совпадают!'
        validation['password_new'] = 'is-invalid'
        validation['password_confirm'] = 'is-invalid'
        feedback['password_new'] = 'invalid-feedback'
        feedback['password_confirm'] = 'invalid-feedback'

    elif request.method == 'POST':
        if (validate_password(params['password_new']), 'success') is not None:
            msg['password_new'] = validate_password(params['password_new'])
            validation['password_new'] = 'is-invalid'
            feedback['password_new'] = 'invalid-feedback'

        with mysql.connection.cursor(named_tuple=True) as cursor:
            cursor.execute(
                'SELECT * FROM users WHERE id=%(user_id)s AND password_hash=SHA2(%(password_old)s, 256);', params)
            db_user = cursor.fetchone()

        if db_user:
            with mysql.connection.cursor(named_tuple=True) as cursor:
                try:
                    cursor.execute(
                        ('UPDATE users SET password_hash=SHA2(%(password_new)s, 256) WHERE id=%(user_id)s;'), params)
                    mysql.connection.commit()
                except connector.Error:
                    flash('Введены некорректные данные. Ошибка сохранения', 'danger')
                    return redirect(url_for(('password')))

            flash('Пароль успешно обновлен.', 'success')
            return redirect(url_for(('index')))

        msg['password_old'] = 'Неверный пароль'
        validation['password_old'] = 'is-invalid'
        feedback['password_old'] = 'invalid-feedback'

    return render_template('password.html', msg=msg, validation=validation, feedback=feedback)

def validate_login(login: str):
    lenp = re.compile(r'.{5,25}')           
    symbolsp = re.compile(r'[a-zA-Z0-9]+')
    msg = None
    if not lenp.match(login):
        msg = 'Логин должен быть длиной от 5 до 25 символов!' 
    
    if not symbolsp.match(login): 
        msg = 'Логин должен состоять только из латинских букв и цифр!'

    return msg

def validate_password(password: str):

    lenp = re.compile(r'.{8,128}')
    uppercharp = re.compile(r'.*[A-ZА-Я]')
    digitp = re.compile(r'.*[0-9]')
    symbolsp = re.compile(r'[a-zA-Zа-яА-Я0-9~!?@#$%^&*\_\-+()[\]{}></\\|\"\'.,:;]+')
    msg = None
    if not lenp.match(password):
        msg = 'Пароль должен быть длиной от 8 до 128 символов!' 
    
    if not uppercharp.match(password): 
        msg = 'В пароле должна быть хотя бы одна заглавная буква!'
    
    if not digitp.match(password):
        msg = 'В пароле должна быть хотя бы одна цифра!'

    if not symbolsp.match(password):
        msg = 'В пароле допускаются латинские и кирилические буквы, цифры и символы ~ ! ? @ # $ % ^ & * _ - + ( ) [ ] { } > < / \ | " \' . , : ;'

    return msg

def validate_fio(name: str):
    p = re.compile(r'[А-Яа-я]')
    if name is None:
        return 'Поле не должно быть пусты!'
    if not p.match(name):
        return 'Допустимы только кириллические буквы!'
    return None

def validate_params(params):
    return {'login':  validate_login(params['login']), 'password': validate_password(params['password']), 'first_name': validate_fio(params['first_name']), 'last_name': validate_fio(params['last_name'])}
