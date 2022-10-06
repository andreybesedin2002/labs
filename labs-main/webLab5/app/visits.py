import math
import io
import datetime
from flask import Blueprint, render_template, session, request, redirect, url_for, flash, send_file
from flask_login import current_user, login_required
from app import mysql
from auth import check_rights

bp = Blueprint('visits', __name__, url_prefix='/visits')


PER_PAGE = 15

def convert_to_csv(records):
    fields = records[0]._fields
    result = 'No,' + ','.join(fields) + '\n'
    for i, record in enumerate(records):
        result += f'{i+1},' + ','.join([str(getattr(record, f, '')) for f in fields]) + '\n'
    return result

def generate_report(records):
    buffer = io.BytesIO()
    buffer.write(convert_to_csv(records).encode('utf-8'))
    buffer.seek(0)
    return buffer



@bp.route('/logs')
@login_required
def logs():
    page = request.args.get('page', 1, type=int)
    if current_user.can('create'):
        with mysql.connection.cursor(named_tuple=True) as cursor:
            cursor.execute('SELECT COUNT(*) AS count FROM visit_logs')
            total_count = cursor.fetchone().count
    else:
        with mysql.connection.cursor(named_tuple=True) as cursor:
            cursor.execute('SELECT COUNT(*) AS count FROM visit_logs WHERE user_id=%s', (current_user.id, ))
            total_count = cursor.fetchone().count
    total_pages = math.ceil(total_count / PER_PAGE)
    if current_user.can('create'):
        with mysql.connection.cursor(named_tuple=True) as cursor:
            cursor.execute('SELECT visit_logs.*, users.first_name, users.last_name, users.middle_name FROM visit_logs LEFT JOIN users ON visit_logs.user_id = users.id ORDER BY visit_logs.created_at DESC LIMIT %s OFFSET %s;', (PER_PAGE, PER_PAGE*(page-1)))
            records = cursor.fetchall()
    else:
        with mysql.connection.cursor(named_tuple=True) as cursor:
            cursor.execute('SELECT visit_logs.*, users.first_name, users.last_name, users.middle_name FROM visit_logs LEFT JOIN users ON visit_logs.user_id = users.id WHERE user_id=%s ORDER BY visit_logs.created_at DESC LIMIT %s OFFSET %s;', (current_user.id, PER_PAGE, PER_PAGE*(page-1)))
            records = cursor.fetchall()
    return render_template('visits/logs.html', records=records, page=page, total_pages=total_pages)


@bp.route('/stats/users')
@check_rights('create')
@login_required
def users_stat():
    query = ('SELECT users.first_name, users.last_name, users.middle_name, count(*) AS count '
               'FROM users RIGHT JOIN visit_logs ON visit_logs.user_id = users.id '
               'GROUP BY visit_logs.user_id '
               'ORDER BY count DESC;' )
    with mysql.connection.cursor(named_tuple=True) as cursor:
        cursor.execute(query)
        records = cursor.fetchall()

    if request.args.get('download_csv'):
        f = generate_report(records)
        filename = datetime.datetime.now().strftime('%d_%m_%Y+%H_%M_%S') + '_users_stat.csv'
        return send_file(f, mimetype='text/csv', as_attachment=True, attachment_filename=filename)

    return render_template('visits/users_stat.html', records=records)


@bp.route('/stats/pages')
@check_rights('create')
@login_required
def pages_stat():
    query = ('SELECT path, count(*) AS count '
               'FROM visit_logs '
               'GROUP BY path '
               'ORDER BY count DESC;' )
    with mysql.connection.cursor(named_tuple=True) as cursor:
        cursor.execute(query)
        records = cursor.fetchall()
    if request.args.get('download_csv'):
            f = generate_report(records)
            filename = datetime.datetime.now().strftime('%d_%m_%Y+%H_%M_%S') + '_pages_stat.csv'
            return send_file(f, mimetype='text/csv', as_attachment=True, attachment_filename=filename)
    return render_template('visits/pages_stat.html', records=records)