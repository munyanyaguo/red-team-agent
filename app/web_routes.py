from flask import Blueprint, render_template

web_bp = Blueprint('web', __name__, template_folder='../UI/templates')

@web_bp.route('/')
def index():
    return render_template('index.html')

@web_bp.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')
