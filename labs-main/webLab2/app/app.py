from flask import Flask, render_template, request, make_response

app = Flask(__name__)
application = app


@app.route('/index')
def index():
    url = request.url
    return render_template('index.html')


@app.route('/args')
def args():
    return render_template('args.html')


@app.route('/headers')
def headers():
    return render_template('headers.html')


@app.route('/cookies')
def cookies():
    response = make_response(render_template('cookies.html'))
    if request.cookies.get('name') is None:
        response.set_cookie('name', 'qq')
    else:
        response.set_cookie('name', 'qq', expires=0)
    return response


@app.route('/form', methods=['GET', 'POST'])
def form():
    return render_template('form.html')


@app.route('/phone', methods=['GET', 'POST'])
def phone():
    error = ''
    tmp = ''
    result = ''
    if request.method == "POST":
        phone = request.form.get("phone")
        count = 0
        for elem in phone:
            if elem.isdigit():
                count += 1
                tmp += elem
            elif elem != '+' and elem != '(' and elem != ')' and elem != '.' and elem != ' ' and elem != '-':
                error = 'Недопустимый ввод. В номере телефона встречаются недопустимые символы.'

        if not error:
            if count == 11:
                if not (phone.startswith('+7') or phone.startswith('8')):
                    error = 'Недопустимый ввод. Неверное количество цифр.'
            elif count == 10:
                if phone.startswith('+7'):
                    error = 'Недопустимый ввод. Неверное количество цифр.'
            else:
                error = 'Недопустимый ввод. Неверное количество цифр.'

        if not error:
            if phone.startswith('+7'):
                result = f'+7-{tmp[1:4]}-{tmp[4:7]}-{tmp[7:9]}-{tmp[9:]}'
            elif phone.startswith('8') and count == 11:
                result = f'8-{tmp[1:4]}-{tmp[4:7]}-{tmp[7:9]}-{tmp[9:]}'
            else:
                result = f'8-{tmp[:3]}-{tmp[3:6]}-{tmp[6:8]}-{tmp[8:]}'
        else:
            result = phone

    return render_template('phone.html', phone=result, error_msg=error)
