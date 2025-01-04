from flask import Flask, render_template, request, redirect, url_for, flash, send_file, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import pandas as pd
from datetime import datetime
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///rehber.db'
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    role = db.Column(db.String(20), nullable=False)

class Contact(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ad_soyad = db.Column(db.String(100), nullable=False)
    telefon = db.Column(db.String(10), nullable=False)
    gorev = db.Column(db.String(100))
    kurum = db.Column(db.String(100))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    @staticmethod
    def validate_phone(phone):
        # Sadece rakamları al
        digits = ''.join(filter(str.isdigit, phone))
        if len(digits) != 10:
            raise ValueError('Telefon numarası 10 haneli olmalıdır!')
        return digits

with app.app_context():
    db.create_all()
    # Admin kullanıcılarını oluştur
    if not User.query.filter_by(username='admin').first():
        admin = User(
            username='admin',
            password_hash=generate_password_hash('1234'),
            role='admin'
        )
        db.session.add(admin)
    
    if not User.query.filter_by(username='sadmin').first():
        superadmin = User(
            username='sadmin',
            password_hash=generate_password_hash('s1234a'),
            role='superadmin'
        )
        db.session.add(superadmin)
    db.session.commit()

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('contacts'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        
        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            return redirect(url_for('contacts'))
        flash('Geçersiz kullanıcı adı veya şifre!', 'danger')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/contacts')
@login_required
def contacts():
    # Get all contacts first to calculate total number
    total_contacts = Contact.query.count()
    
    # Calculate number of tabs needed (20 contacts per tab)
    num_tabs = (total_contacts + 19) // 20  # Round up division
    
    # Get current tab from query parameters, default to 1
    current_tab = request.args.get('tab', 1, type=int)
    
    # Ensure current_tab is within valid range
    current_tab = max(1, min(current_tab, num_tabs)) if num_tabs > 0 else 1
    
    # Calculate offset and get contacts for current tab
    offset = (current_tab - 1) * 20
    contacts = Contact.query.order_by(Contact.ad_soyad).offset(offset).limit(20).all()
    
    return render_template('contacts.html', 
                         contacts=contacts,
                         current_tab=current_tab,
                         num_tabs=num_tabs)

@app.route('/add_contact', methods=['POST'])
@login_required
def add_contact():
    if current_user.role != 'superadmin':
        flash('Bu işlem için yetkiniz yok!', 'danger')
        return redirect(url_for('contacts'))
    
    try:
        telefon = Contact.validate_phone(request.form.get('telefon'))
        contact = Contact(
            ad_soyad=request.form.get('ad_soyad'),
            telefon=telefon,
            gorev=request.form.get('gorev'),
            kurum=request.form.get('kurum')
        )
        db.session.add(contact)
        db.session.commit()
        flash('Kişi başarıyla eklendi!', 'success')
    except ValueError as e:
        flash(str(e), 'danger')
    return redirect(url_for('contacts'))

@app.route('/delete_contact/<int:id>')
@login_required
def delete_contact(id):
    if current_user.role != 'superadmin':
        flash('Bu işlem için yetkiniz yok!', 'danger')
        return redirect(url_for('contacts'))
    
    contact = Contact.query.get_or_404(id)
    db.session.delete(contact)
    db.session.commit()
    flash('Kişi başarıyla silindi!', 'success')
    return redirect(url_for('contacts'))

@app.route('/update_contact/<int:id>', methods=['POST'])
@login_required
def update_contact(id):
    if current_user.role != 'superadmin':
        flash('Bu işlem için yetkiniz yok!', 'danger')
        return redirect(url_for('contacts'))
    
    try:
        contact = Contact.query.get_or_404(id)
        telefon = Contact.validate_phone(request.form.get('telefon'))
        contact.ad_soyad = request.form.get('ad_soyad')
        contact.telefon = telefon
        contact.gorev = request.form.get('gorev')
        contact.kurum = request.form.get('kurum')
        db.session.commit()
        flash('Kişi başarıyla güncellendi!', 'success')
    except ValueError as e:
        flash(str(e), 'danger')
    return redirect(url_for('contacts'))

@app.route('/export_excel')
@login_required
def export_excel():
    if current_user.role != 'superadmin':
        flash('Bu işlem için yetkiniz yok!', 'danger')
        return redirect(url_for('contacts'))
    
    contacts = Contact.query.all()
    data = []
    for contact in contacts:
        data.append({
            'Ad Soyad': contact.ad_soyad,
            'Telefon': contact.telefon,
            'Görev': contact.gorev,
            'Kurum': contact.kurum,
            'Oluşturulma Tarihi': contact.created_at
        })
    df = pd.DataFrame(data)
    excel_file = 'rehber_export.xlsx'
    df.to_excel(excel_file, index=False)
    return send_file(excel_file, as_attachment=True)

@app.route('/import_excel', methods=['POST'])
@login_required
def import_excel():
    if current_user.role != 'superadmin':
        flash('Bu işlem için yetkiniz yok!', 'danger')
        return redirect(url_for('contacts'))
    
    if 'excel_file' not in request.files:
        flash('Excel dosyası seçilmedi!', 'danger')
        return redirect(url_for('contacts'))
    
    file = request.files['excel_file']
    if file.filename == '':
        flash('Dosya seçilmedi!', 'danger')
        return redirect(url_for('contacts'))
    
    try:
        df = pd.read_excel(file)
        success_count = 0
        error_count = 0
        
        for _, row in df.iterrows():
            try:
                telefon = Contact.validate_phone(str(row['Telefon']))
                contact = Contact(
                    ad_soyad=row['Ad Soyad'],
                    telefon=telefon,
                    gorev=row['Görev'] if 'Görev' in df.columns else '',
                    kurum=row['Kurum'] if 'Kurum' in df.columns else ''
                )
                db.session.add(contact)
                success_count += 1
            except ValueError:
                error_count += 1
                continue
                
        db.session.commit()
        if error_count > 0:
            flash(f'{success_count} kişi başarıyla eklendi, {error_count} kişi hatalı telefon numarası nedeniyle eklenemedi!', 'warning')
        else:
            flash(f'{success_count} kişi başarıyla içe aktarıldı!', 'success')
    except Exception as e:
        flash(f'Dosya içe aktarılırken hata oluştu: {str(e)}', 'danger')
    
    return redirect(url_for('contacts'))

@app.route('/delete_selected', methods=['POST'])
@login_required
def delete_selected():
    if current_user.role != 'superadmin':
        flash('Bu işlem için yetkiniz yok!', 'danger')
        return redirect(url_for('contacts'))
    
    contact_ids = request.form.getlist('contact_ids[]')
    if not contact_ids:
        flash('Silinecek kişi seçilmedi!', 'danger')
        return redirect(url_for('contacts'))
    
    try:
        Contact.query.filter(Contact.id.in_(contact_ids)).delete(synchronize_session=False)
        db.session.commit()
        flash('Seçili kişiler başarıyla silindi!', 'success')
    except Exception as e:
        flash(f'Kişiler silinirken hata oluştu: {str(e)}', 'danger')
    
    return redirect(url_for('contacts'))

@app.route('/search_contacts')
@login_required
def search_contacts():
    search = request.args.get('search', '')
    search_by = request.args.get('search_by', 'ad_soyad')
    
    query = Contact.query
    
    if search:
        if search_by == 'ad_soyad':
            query = query.filter(Contact.ad_soyad.ilike(f'%{search}%'))
        elif search_by == 'telefon':
            query = query.filter(Contact.telefon.ilike(f'%{search}%'))
        elif search_by == 'gorev':
            query = query.filter(Contact.gorev.ilike(f'%{search}%'))
        elif search_by == 'kurum':
            query = query.filter(Contact.kurum.ilike(f'%{search}%'))
    
    contacts = query.order_by(Contact.ad_soyad).limit(20).all()
    
    results = []
    for contact in contacts:
        results.append({
            'id': contact.id,
            'ad_soyad': contact.ad_soyad,
            'telefon': contact.telefon,
            'gorev': contact.gorev or '',
            'kurum': contact.kurum or ''
        })
    
    return jsonify(results)

if __name__ == '__main__':
    import os
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port)
