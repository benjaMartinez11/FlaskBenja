import functools

from flask import (
    Blueprint, flash, g, redirect, render_template, request, session, url_for
)
from werkzeug.security import check_password_hash, generate_password_hash

from Flaskr.db import get_db

bp = Blueprint('auth', __name__, url_prefix='/auth')

@bp.route('/register', methods=('GET', 'POST'))
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        verficar_contra = request.form['verificar_contra']
        email = request.form['email']
        db = get_db()
        error = None

        if not username:
            error = 'El usuario no coninside.'
        elif not password:
            error = 'Se requiere contraseña.'
        elif verficar_contra !=  password:
            error = 'Contraseñas no coinciden.' 
        elif not email:
            error = 'se requiere email'   

        if error is None:
            try:
                db.execute(
                    "INSERT INTO user (username, password, verificar_contra) VALUES (?, ?, ?)",
                    (username, generate_password_hash(password), verficar_contra),
                )
                db.commit()
            except db.IntegrityError:
                error = f"User {username} is already registered."
            else:
                return redirect(url_for("auth.login"))

        flash(error)

    return render_template('auth/register.html')

@bp.route('/login', methods=('GET', 'POST'))
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        db = get_db()
        error = None
        user = db.execute(
            'SELECT * FROM user WHERE username = ?', (username,)
        ).fetchone()

        if user is None:
            error = 'Incorrect username.'
        elif not check_password_hash(user['password'], password):
            error = 'Incorrect password.'

        if error is None:
            session.clear()
            session['user_id'] = user['id']
            return redirect(url_for('index'))

        flash(error)

    return render_template('auth/login.html')

@bp.before_app_request
def load_logged_in_user():
    user_id = session.get('user_id')

    if user_id is None:
        g.user = None
    else:
        g.user = get_db().execute(
            'SELECT * FROM user WHERE id = ?', (user_id,)
        ).fetchone()

@bp.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

def login_required(view):
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if g.user is None:
            return redirect(url_for('auth.login'))

        return view(**kwargs)

    return wrapped_view

@bp.route('/.....', methods=('GET', 'POST'))
def update():
    if request.method == 'POST':
        email = request.form['nuevo_email']
        error = None
        db = get_db()

        if not title:
            error = 'Title is required.'

        if error is not None:
            
            db.execute(
                'UPDATE user SET email = ? WHERE id = ?',
                (email, g.user[id],)
            )
            db.commit()
            return redirect(url_for('index'))

    return render_template('auth/.... .html')