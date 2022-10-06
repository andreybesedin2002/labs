from flask import Blueprint, render_template, request, flash, redirect, url_for
from flask_login import login_required


from app import db
from models import Category, Course, User
from tools import CoursesFilter

bp = Blueprint('courses', __name__, url_prefix='/courses')

COURSE_PARAMS = ['name', 'short_desc', 'full_desc', 'author_id', 'category_id']
PER_PAGE = 3

def params():
    return { p: request.form.get(p) for p in COURSE_PARAMS }

def search_params():
    return {
        'name': request.args.get('name'),
        'category_ids': request.args.getlist('category_ids')
    }

@bp.route('/')
def index():
    page = request.args.get('page', 1, type=int)
    courses = CoursesFilter(**search_params()).perform()
    pagination = courses.paginate(page, PER_PAGE)
    courses = pagination.items
    categories = Category.query.all()
    return render_template('courses/index.html', 
                            courses=courses,
                            categories=categories,
                            search_params=search_params(),
                            pagination=pagination)

@bp.route('/new')
def new():
    categories = Category.query.all()
    users = User.query.all()
    return render_template('courses/new.html', categories=categories, users=users)

@bp.route('/create', methods=['POST'])
def create():
    
    course = Course(**params())
    db.session.add(course)
    db.session.commit()

    flash(f'Курс { course.name } был успешно создан!', 'success')
    return  redirect(url_for('courses.index'))

@bp.route('/<int:course_id>')
def show(course_id):
    course = Course.query.get(course_id)

    return render_template('courses/show.html', course=course)