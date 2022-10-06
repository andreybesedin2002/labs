from flask import Flask, render_template

app = Flask(__name__)

application = app

@app.route('/')

def index():
    return render_template('index.html')

@app.route('/posts')

def posts():
    msg = 'Hello'
    return render_template('posts.html')

@app.route('/about')
def about():
    return render_template('about.html')