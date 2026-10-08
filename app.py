import os
from datetime import datetime, timedelta
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import or_
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from functools import wraps

app = Flask(__name__)

# ---------------------------------------------------------------------------
# App & Session Configuration
# ---------------------------------------------------------------------------
app.config['SECRET_KEY'] = 'pesona-helpdesk-secret-key-2026'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///pesona_helpdesk.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Konfigurasi Session & Cookie yang Stabil
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_REFRESH_EACH_REQUEST'] = True

UPLOAD_FOLDER = os.path.join('static', 'uploads')
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

db = SQLAlchemy(app)

# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------
class Unit(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    users = db.relationship('User', backref='unit', lazy=True)

class Category(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    tickets = db.relationship('Ticket', backref='category', lazy=True)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    unit_id = db.Column(db.Integer, db.ForeignKey('unit.id'), nullable=False)
    role = db.Column(db.String(20), default='User')  # 'Admin' or 'User'
    tickets = db.relationship('Ticket', backref='author', lazy=True)

class Ticket(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ticket_no = db.Column(db.String(20), unique=True, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    category_id = db.Column(db.Integer, db.ForeignKey('category.id'), nullable=False)
    priority = db.Column(db.String(10), nullable=False)  # Low, Med, High
    status = db.Column(db.String(15), default='NEW')     # NEW -> PROGRESS -> DONE -> CLOSED
    content = db.Column(db.Text, nullable=False)
    notes = db.Column(db.Text, nullable=True)             # Catatan Tim Support
    image_path = db.Column(db.String(255), nullable=True)
    closed_acknowledged = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.now)
    updated_at = db.Column(db.DateTime, default=datetime.now, onupdate=datetime.now)

# ---------------------------------------------------------------------------
# PWA Routes
# ---------------------------------------------------------------------------
@app.route('/manifest.json')
def manifest():
    return send_from_directory('static', 'manifest.json')

@app.route('/sw.js')
def service_worker():
    return send_from_directory('static', 'sw.js')

# ---------------------------------------------------------------------------
# Helpers & Middleware
# ---------------------------------------------------------------------------
@app.context_processor
def inject_assets():
    def asset_exists(filename):
        return os.path.exists(os.path.join(app.static_folder, filename))
    return dict(asset_exists=asset_exists)

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            if request.path.startswith('/api/'):
                return jsonify({'error': 'Unauthorized', 'redirect': url_for('login')}), 401
            flash('Please log in first to access PesonaHelpdesk.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get('role') != 'Admin':
            if request.path.startswith('/api/'):
                return jsonify({'error': 'Forbidden'}), 403
            flash('Access denied. Administrator privileges required.', 'danger')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

# ---------------------------------------------------------------------------
# Auth Routes
# ---------------------------------------------------------------------------
@app.route('/', methods=['GET', 'POST'])
@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password_hash, password):
            session.clear()
            session.permanent = True
            session['user_id'] = user.id
            session['name'] = user.name
            session['username'] = user.username
            session['role'] = user.role
            session['unit_id'] = user.unit_id
            session['unit_name'] = user.unit.name if user.unit else '-'
            return redirect(url_for('dashboard'))
        
        flash('Invalid username or password.', 'danger')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out successfully from PesonaHelpdesk.', 'info')
    return redirect(url_for('login'))

# ---------------------------------------------------------------------------
# Dashboard & Tickets
# ---------------------------------------------------------------------------
@app.route('/dashboard')
@login_required
def dashboard():
    is_admin = (session.get('role') == 'Admin')
    base_query = Ticket.query if is_admin else Ticket.query.filter_by(user_id=session['user_id'])

    counts = {
        'NEW': base_query.filter(Ticket.status == 'NEW').count(),
        'PROGRESS': base_query.filter(Ticket.status == 'PROGRESS').count(),
        'DONE': base_query.filter(Ticket.status == 'DONE').count(),
        'CLOSED': base_query.filter(Ticket.status == 'CLOSED').count(),
    }
    recent_tickets = base_query.order_by(Ticket.created_at.desc()).limit(5).all()
    return render_template('dashboard.html', counts=counts, tickets=recent_tickets)

@app.route('/tickets')
@login_required
def tickets_list():
    status_filter = request.args.get('status', 'ALL').upper()
    user_filter = request.args.get('user_id', type=int)
    search_q = request.args.get('q', '').strip()
    sort_by = request.args.get('sort_by', 'date_desc')

    is_admin = (session.get('role') == 'Admin')
    
    query = Ticket.query.join(User).join(Category)

    if not is_admin:
        query = query.filter(Ticket.user_id == session['user_id'])
    elif user_filter:
        query = query.filter(Ticket.user_id == user_filter)

    if status_filter in ['NEW', 'PROGRESS', 'DONE', 'CLOSED']:
        query = query.filter(Ticket.status == status_filter)
    elif status_filter == 'ACTIVE':
        query = query.filter(Ticket.status == 'NEW')

    if search_q:
        pattern = f"%{search_q}%"
        query = query.filter(
            or_(
                Ticket.ticket_no.ilike(pattern),
                Ticket.content.ilike(pattern),
                User.name.ilike(pattern),
                Category.name.ilike(pattern)
            )
        )

    if sort_by == 'date_asc':
        query = query.order_by(Ticket.created_at.asc())
    elif sort_by == 'user_asc':
        query = query.order_by(User.name.asc())
    elif sort_by == 'user_desc':
        query = query.order_by(User.name.desc())
    else:  # date_desc
        query = query.order_by(Ticket.created_at.desc())

    tickets = query.all()
    all_users = User.query.order_by(User.name.asc()).all() if is_admin else []

    return render_template('tickets.html',
                           tickets=tickets,
                           current_filter=status_filter,
                           all_users=all_users,
                           current_user_filter=user_filter,
                           current_q=search_q,
                           current_sort=sort_by)

@app.route('/ticket/create', methods=['GET', 'POST'])
@login_required
def create_ticket():
    if request.method == 'POST':
        category_id = request.form.get('category_id')
        priority = request.form.get('priority')
        content = request.form.get('content')

        image_filename = None
        if 'image' in request.files:
            file = request.files['image']
            if file and file.filename != '':
                filename = secure_filename(f"{int(datetime.now().timestamp())}_{file.filename}")
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                image_filename = filename

        ticket_count = Ticket.query.count() + 1
        ticket_no = f"TCK-{ticket_count:04d}"

        new_ticket = Ticket(
            ticket_no=ticket_no,
            user_id=session['user_id'],
            category_id=category_id,
            priority=priority,
            content=content,
            image_path=image_filename,
            status='NEW'
        )
        db.session.add(new_ticket)
        db.session.commit()
        flash('Ticket created successfully!', 'success')
        return redirect(url_for('tickets_list'))

    categories = Category.query.all()
    return render_template('create_ticket.html', categories=categories)

@app.route('/ticket/advance/<int:ticket_id>', methods=['POST'])
@login_required
def advance_ticket_status(ticket_id):
    ticket = Ticket.query.get_or_404(ticket_id)
    is_admin = (session.get('role') == 'Admin')
    current_user_id = session['user_id']

    if is_admin:
        if ticket.status == 'NEW':
            ticket.status = 'PROGRESS'
            db.session.commit()
            flash(f'Ticket {ticket.ticket_no} status changed to IN PROGRESS.', 'success')
        elif ticket.status == 'PROGRESS':
            ticket.status = 'DONE'
            db.session.commit()
            flash(f'Ticket {ticket.ticket_no} status changed to DONE.', 'success')
        elif ticket.status == 'DONE' and ticket.user_id == current_user_id:
            ticket.status = 'CLOSED'
            ticket.closed_acknowledged = False
            db.session.commit()
            flash(f'Ticket {ticket.ticket_no} confirmed and CLOSED.', 'success')
        else:
            flash('Admin can only advance tickets from NEW to PROGRESS and PROGRESS to DONE.', 'warning')
    else:
        if ticket.user_id == current_user_id and ticket.status == 'DONE':
            ticket.status = 'CLOSED'
            ticket.closed_acknowledged = False
            db.session.commit()
            flash(f'Ticket {ticket.ticket_no} confirmed and CLOSED.', 'success')
        else:
            flash('Users can only close tickets that are marked as DONE.', 'danger')

    return redirect(request.referrer or url_for('tickets_list'))

@app.route('/ticket/update_notes/<int:ticket_id>', methods=['POST'])
@login_required
def update_ticket_notes(ticket_id):
    ticket = Ticket.query.get_or_404(ticket_id)
    is_admin = (session.get('role') == 'Admin')

    if not is_admin:
        flash('Only support team / admin can edit support notes.', 'danger')
        return redirect(request.referrer or url_for('tickets_list'))

    notes = request.form.get('notes', '').strip()
    ticket.notes = notes
    db.session.commit()
    flash(f'Support notes updated for ticket {ticket.ticket_no}.', 'success')
    return redirect(request.referrer or url_for('tickets_list'))

# ---------------------------------------------------------------------------
# Realtime Sidebar Badge & AI Suggestion APIs
# ---------------------------------------------------------------------------
@app.route('/api/sidebar-badge')
@login_required
def sidebar_badge():
    is_admin = (session.get('role') == 'Admin')
    user_id = session['user_id']

    if is_admin:
        new_count = Ticket.query.filter_by(status='NEW').count()
        closed_count = Ticket.query.filter_by(status='CLOSED', closed_acknowledged=False).count()
        return jsonify({
            'role': 'Admin',
            'new': new_count,
            'closed': closed_count,
            'progress': 0,
            'done': 0,
            'total': new_count + closed_count
        })
    else:
        progress_count = Ticket.query.filter_by(user_id=user_id, status='PROGRESS').count()
        done_count = Ticket.query.filter_by(user_id=user_id, status='DONE').count()
        return jsonify({
            'role': 'User',
            'new': 0,
            'closed': 0,
            'progress': progress_count,
            'done': done_count,
            'total': progress_count + done_count
        })

@app.route('/api/clear-closed-notifications', methods=['POST'])
@login_required
@admin_required
def clear_closed_notifications():
    Ticket.query.filter_by(status='CLOSED', closed_acknowledged=False).update({Ticket.closed_acknowledged: True})
    db.session.commit()
    return jsonify({'success': True})

@app.route('/api/suggest-ai', methods=['POST'])
@login_required
def suggest_ai():
    data = request.get_json() or {}
    user_text = data.get('text', '').strip()

    if not user_text:
        return jsonify({'success': False, 'message': 'Please type a short description first.'})

    formatted_ai = f"""<p><strong>[SUMMARY OF ISSUE]</strong></p>
<p>{user_text}</p>
<p><strong>[OBSERVATION & DETAILS]</strong></p>
<ul>
    <li>The issue prevents standard operation in our unit workflow.</li>
    <li>Basic preliminary check performed; requires technical support intervention.</li>
</ul>
<p><strong>[REQUESTED ACTION]</strong></p>
<p>Please inspect and resolve this issue as soon as possible. Thank you.</p>"""

    return jsonify({'success': True, 'suggestion': formatted_ai})

# ---------------------------------------------------------------------------
# Admin Management Routes
# ---------------------------------------------------------------------------
@app.route('/admin/users', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_users():
    if request.method == 'POST':
        name = request.form.get('name')
        username = request.form.get('username')
        password = request.form.get('password')
        unit_id = request.form.get('unit_id')
        role = request.form.get('role', 'User')

        if User.query.filter_by(username=username).first():
            flash('Username is already taken.', 'danger')
        else:
            hashed_pw = generate_password_hash(password)
            user = User(name=name, username=username, password_hash=hashed_pw, unit_id=unit_id, role=role)
            db.session.add(user)
            db.session.commit()
            flash('User created successfully.', 'success')
        return redirect(url_for('admin_users'))

    users = User.query.all()
    units = Unit.query.all()
    return render_template('admin_users.html', users=users, units=units)

@app.route('/admin/users/reset/<int:user_id>', methods=['POST'])
@login_required
@admin_required
def reset_password(user_id):
    user = User.query.get_or_404(user_id)
    new_pw = request.form.get('new_password')
    user.password_hash = generate_password_hash(new_pw)
    db.session.commit()
    flash(f'Password for {user.username} reset successfully.', 'success')
    return redirect(url_for('admin_users'))

@app.route('/admin/users/delete/<int:user_id>', methods=['POST'])
@login_required
@admin_required
def delete_user(user_id):
    if user_id == session['user_id']:
        flash('Cannot delete your active session account.', 'danger')
        return redirect(url_for('admin_users'))
    user = User.query.get_or_404(user_id)
    db.session.delete(user)
    db.session.commit()
    flash('User deleted successfully.', 'success')
    return redirect(url_for('admin_users'))

@app.route('/admin/categories', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_categories():
    if request.method == 'POST':
        name = request.form.get('name')
        if name and not Category.query.filter_by(name=name).first():
            db.session.add(Category(name=name))
            db.session.commit()
            flash('Category added successfully.', 'success')
        else:
            flash('Category already exists or invalid.', 'warning')
        return redirect(url_for('admin_categories'))

    categories = Category.query.all()
    return render_template('admin_categories.html', categories=categories)

@app.route('/admin/units', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_units():
    if request.method == 'POST':
        name = request.form.get('name')
        if name and not Unit.query.filter_by(name=name).first():
            db.session.add(Unit(name=name))
            db.session.commit()
            flash('Unit added successfully.', 'success')
        else:
            flash('Unit already exists or invalid.', 'warning')
        return redirect(url_for('admin_units'))

    units = Unit.query.all()
    return render_template('admin_units.html', units=units)

def init_db():
    with app.app_context():
        db.create_all()
        try:
            with db.engine.connect() as conn:
                conn.execute(db.text("ALTER TABLE ticket ADD COLUMN image_path VARCHAR(255)"))
                conn.commit()
        except Exception:
            pass
        try:
            with db.engine.connect() as conn:
                conn.execute(db.text("ALTER TABLE ticket ADD COLUMN closed_acknowledged BOOLEAN DEFAULT 0"))
                conn.commit()
        except Exception:
            pass
        try:
            with db.engine.connect() as conn:
                conn.execute(db.text("ALTER TABLE ticket ADD COLUMN notes TEXT"))
                conn.commit()
        except Exception:
            pass

        if not Unit.query.first():
            it_unit = Unit(name='IT Support')
            hr_unit = Unit(name='General HR')
            db.session.add_all([it_unit, hr_unit])
            db.session.commit()

        if not Category.query.first():
            c1 = Category(name='Hardware')
            c2 = Category(name='Software')
            c3 = Category(name='Network')
            db.session.add_all([c1, c2, c3])
            db.session.commit()

        if not User.query.filter_by(username='admin').first():
            it_unit = Unit.query.filter_by(name='IT Support').first()
            admin_user = User(
                name='Pesona Admin',
                username='admin',
                password_hash=generate_password_hash('admin123'),
                unit_id=it_unit.id,
                role='Admin'
            )
            db.session.add(admin_user)
            db.session.commit()

if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=5005, debug=True)