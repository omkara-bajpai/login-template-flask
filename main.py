from flask import Flask, render_template, request, flash, redirect, session
from flask_sqlalchemy import SQLAlchemy
from datetime import timedelta
app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///db.sqlite3"
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=10)
app.secret_key = 'Super secret key'
db = SQLAlchemy(app)


class User(db.Model):
    sno = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(2000), unique=True, nullable=False)
    password = db.Column(db.String(2000), nullable=False)


@app.route("/login", methods=['GET', 'POST'])
def login():
    if 'user' not in session:
        if request.method == 'POST':
            email = request.form.get('email')
            password = request.form.get('password')
            emails = []
            passs = []
            for query in User.query.filter_by().all():
                emails.append(query.email)
                passs.append(query.password)
            if email != '' and password != '':
                if email in emails:
                    if passs[emails.index(email)] == password:
                        session['user'] = email
                        return redirect('/dashboard')
                    else:
                        flash('The email or password is wrong')
                else:
                    flash('The email or password is wrong')
            else:
                flash('The email or password is blank')

        return render_template('login.html')
    else:
        return redirect('/dashboard')


@app.route("/dashboard")
def dashboard():
    if 'user' in session:
        data = User.query.filter_by().all()
        data_email = []
        for email in data:
            data_email.append(email.email)
        if session['user'] in data_email:
            return render_template('home.html')
        else:
            del session['user']
            return redirect('/login')
    else:
        return redirect('/login')


@app.route("/")
def blank():
    if 'user' in session:
        return redirect('/dashboard')
    else:
        return redirect('/login')


@app.route('/logout')
def logout():
    if 'user' in session:
        del session['user']
        return redirect('/login')
    else:
        return redirect('/login')


@app.route('/account')
def account():
    if 'user' in session:
        data = User.query.filter_by().all()
        data_email = []
        for email in data:
            data_email.append(email.email)
        if session['user'] in data_email:
            query = User.query.filter_by(email=session['user']).first()
            return render_template('account.html', query=query)
        else:
            del session['user']
            return redirect('/login')
    else:
        return redirect('/login')


@app.route("/sign", methods=['GET', 'POST'])
def sign():
    if 'user' not in session:
        if request.method == 'POST':
            email = request.form.get('email')
            passw = request.form.get('pass')
            confirm = request.form.get('confirm')
            if (email != '') and (passw != '') and (confirm != ''):
                if (passw == confirm):
                    if (len(email) < 200) and (len(passw) < 200) and (len(confirm) < 200):
                        try:
                            data = User(email=email, password=passw)
                            db.session.add(data)
                            db.session.commit()
                            session['user'] = email
                            return redirect('/dashboard')

                        except:
                            flash(
                                'The email is already taken please select and other email')
                    else:
                        flash(
                            'The email or password is very big please select some small email or password')
                else:
                    flash('The password is not matching the confirm password')

            else:
                flash('The email or password on firm password cant be blank')

        return render_template('signin.html')
    else:
        return redirect('/dashboard')


@app.route('/account/edit', methods=['GET', 'POST'])
def account_edit():
    if 'user' in session:
        data = User.query.filter_by().all()
        data_email = []
        for email in data:
            data_email.append(email.email)
        if session['user'] in data_email:
            if request.method == 'POST':
                new = request.form.get('email')
                query = User.query.filter_by(email=session['user']).first()
                if new != '':
                    if len(new) < 200:
                        if new != session['user']:
                            data = User.query.filter_by().all()
                            data_email = []
                            for email in data:
                                data_email.append(email.email)
                            if new not in data_email:
                                query = User.query.filter_by(
                                    email=session['user']).first()
                                query.email = new
                                db.session.add(query)
                                db.session.commit()

                                session['user'] = new
                                return redirect('/account')
                            else:
                                flash('This email is already taken')
                        else:
                            return redirect('/account')
                    else:
                        flash('The email is very big')
                else:
                    flash('The email cant be blank')
            query = User.query.filter_by(email=session['user']).first()
            return render_template('account_edit.html', query=query)
        else:
            del session['user']
            return redirect('/login')
    else:
        return redirect('/login')


@app.route('/account/edit/pass', methods=['GET', 'POST'])
def account_edit_pass():
    if 'user' in session:
        data = User.query.filter_by().all()
        data_email = []
        for email in data:
            data_email.append(email.email)
        if session['user'] in data_email:
            if request.method == 'POST':
                query = User.query.filter_by(email=session['user']).first()
                old = request.form.get('old')
                new = request.form.get('new')
                confirm = request.form.get('confirm')

                if (new != "") and (old != "") and (confirm != ''):
                    if (len(new) < 2000) and (len(confirm) < 2000):
                        if new == confirm:
                            if old == query.password:
                                query.password = new
                                db.session.add(query)
                                db.session.commit()
                                return redirect('/account')
                            else:
                                flash('The old password is wrong')
                        else:
                            flash(
                                'The new password isnt matching the new confirm password')
                    else:
                        flash('The new password cant be very big')
                else:
                    flash('Please fill every fields')

            query = User.query.filter_by(email=session['user']).first()
            return render_template('account_edit_password.html', query=query)
        else:
            del session['user']
            return redirect('/login')
    else:
        return redirect('/login')


@app.route('/account/delete', methods=['GET', 'POST'])
def delete():
    if 'user' in session:
        data = User.query.filter_by().all()
        data_email = []
        for email in data:
            data_email.append(email.email)
        if session['user'] in data_email:
            if request.method == 'POST':
                email = request.form.get('email')
                password = request.form.get('pass')
                query = User.query.filter_by(email=session['user']).first()
                if email != "" and password != '':
                    if email == session['user'] and password == query.password:
                        db.session.delete(query)
                        db.session.commit()

                        return redirect('/login')
                    else:
                        flash('The email or password is not correct')
                else:
                    flash('The email or password cant be blank')

            return render_template('delete.html')
        else:
            del session['user']
            return redirect('/login')
    else:
        return redirect('/login')


@app.before_request
def make_session_permanent():
    session.permanent = True


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
