# app.py
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from datetime import datetime
from flask_migrate import Migrate
from flask_bcrypt import Bcrypt
from flask_wtf import CSRFProtect

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'  # Replace with your own secret key
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite3'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
csrf = CSRFProtect(app)
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
migrate = Migrate(app, db)

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    medicines = db.relationship('Medicine', backref='user', lazy=True)

class Medicine(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    tablet_color = db.Column(db.String(150), nullable=False)
    liquid_color = db.Column(db.String(150), nullable=False)
    date_taken = db.Column(db.DateTime, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    comments = db.Column(db.String(500), nullable=True)

class TabletColor(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    color = db.Column(db.String(10), nullable=False, unique = True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    # Establishing a relationship with the Medicine model
    # medicines = db.relationship('Medicine', foreign_keys='[Medicine.tablet_color_id]', backref='tablet_color_rel', lazy=True)

class LiquidColor(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    color = db.Column(db.String(10), nullable=False, unique = True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    # Establishing a relationship with the Medicine model
    # medicines = db.relationship('Medicine', foreign_keys='[Medicine.liquid_color_id]', backref='liquid_color_rel', lazy=True)

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

@app.route('/add_medicine', methods=['GET', 'POST'])
@login_required
def add_medicine():
    if request.method == 'POST':
        tablet_color = request.form.get('tablet_color')
        liquid_color = request.form.get('liquid_color')
        date_taken_str = request.form.get('date_taken')
        comments = request.form.get('comments')
        if not tablet_color or not liquid_color:
            flash('Both tablet and liquid colors are required!')
            return redirect(url_for('add_medicine'))
        # Convert date string to datetime object
        try:
            date_taken = datetime.strptime(date_taken_str, '%Y-%m-%d')
        except ValueError:
            flash('Invalid date format. Please use YYYY-MM-DD.', 'danger')
            return redirect(url_for('add_medicine'))
        new_medicine = Medicine(tablet_color=tablet_color, liquid_color=liquid_color,date_taken=date_taken, user_id=current_user.id, comments=comments)
        db.session.add(new_medicine)
        db.session.commit()
        flash('Medicine added successfully!')
        return redirect(url_for('index'))
    tablet_colors = db.session.query(TabletColor.color).filter_by(user_id=current_user.id).all()
    liquid_colors = db.session.query(LiquidColor.color).filter_by(user_id=current_user.id).all()
    tablet_colors = [color[0] for color in tablet_colors]
    liquid_colors = [color[0] for color in liquid_colors]
    return render_template('add_medicine.html', tablet_colors=tablet_colors, liquid_colors=liquid_colors)

@app.route('/')
@login_required
def index():
    medicines = Medicine.query.filter_by(user_id=current_user.id).order_by(Medicine.date_taken.asc())
    return render_template('index.html', medicines=medicines)

@app.errorhandler(404)
def page_not_found(error):
    return render_template('page_not_found.html'), 404

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        new_user = User(username=username, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        flash('Your account has been created! You can now log in', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('index'))
        else:
            flash('Login Unsuccessful. Please check username and password', 'danger')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/add', methods=['POST'])
@login_required
def add():
    medicine_name = request.form.get('name')
    if medicine_name:
        new_medicine = Medicine(name=medicine_name, user_id=current_user.id)
        db.session.add(new_medicine)
        db.session.commit()
    return redirect(url_for('index'))

@app.route('/colors', methods=['POST', 'GET'])
@login_required
def colors():
    if request.method == 'POST':
        if request.form.get('tablet_color'):
            tabletColor = request.form.get('tablet_color').capitalize()
            newTabletColor = TabletColor(color = tabletColor, user_id = current_user.id)
            db.session.add(newTabletColor)
        
        if request.form.get('liquid_color'):
            liquidColor = request.form.get('liquid_color').capitalize()
            newLiquidColor = LiquidColor(color = liquidColor, user_id = current_user.id)
            db.session.add(newLiquidColor)
        try:
            db.session.commit()
        except Exception as e:
            flash('Error: ' + str(e), 'danger')

        if not request.form.get('tablet_color') and not request.form.get('liquid_color'):
            flash('Both tablet and liquid colors are required!')
            return redirect(url_for('addTabletColor'))
        return redirect(url_for('colors'))
    tablet_colors = db.session.query(TabletColor.color).filter_by(user_id=current_user.id).all()
    liquid_colors = db.session.query(LiquidColor.color).filter_by(user_id=current_user.id).all()
    tablet_colors = [color[0] for color in tablet_colors]
    liquid_colors = [color[0] for color in liquid_colors]
    return render_template('add_tabletColor.html', tablet_colors = tablet_colors, liquid_colors = liquid_colors, size = max(len(tablet_colors), len(liquid_colors)))


def delete_tablet_color_entry(tablet_color_id):
    # Fetch the TabletColor entry to delete
    tablet_color = TabletColor.query.get(tablet_color_id)
    
    if tablet_color:
        # Delete the TabletColor entry
        db.session.delete(tablet_color)
        db.session.commit()
        return True
    else:
        return False
        
@app.route('/delete_medicine/<int:id>', methods=['POST'])
@login_required
def delete_medicine(id):
    medicine = Medicine.query.get_or_404(id)
    if medicine.user_id != current_user.id:
        flash('You do not have permission to delete this medicine.', 'danger')
        return redirect(url_for('index'))
    
    db.session.delete(medicine)
    db.session.commit()
    
    flash('Medicine entry deleted successfully!', 'success')
    return redirect(url_for('index'))

@app.route('/update/medicine/<int:id>', methods=['POST'])
@login_required
def update_medicine(id):
    medicine = Medicine.query.get_or_404(id)
    if medicine.user_id != current_user.id:
        flash('You do not have permission to delete this medicine.', 'danger')
        return redirect(url_for('index'))
    if request.method == 'POST':
        medicine.date_taken = request.form.get("date_taken")
        medicine.liquid_color = request.form.get("liquid_color")
        medicine.tablet_color = request.form.get("tablet_color")
        medicine.comments = request.form.get("comments")
        db.session.commit()
        flash('Medicine entry updated successfully!', 'success')
    return redirect(url_for('index'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
