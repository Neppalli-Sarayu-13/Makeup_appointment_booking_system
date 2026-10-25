
from flask import Flask, render_template, url_for, request, redirect, flash, session, jsonify
from flask_session import Session
from otp import genotp
import razorpay
from stoken import endata, dndata
from cmail import send_mail, send_user_appointment_email, send_user_cancel_email
from flask_bcrypt import Bcrypt
from werkzeug.security import generate_password_hash, check_password_hash
import os
from datetime import datetime
from werkzeug.utils import secure_filename
from mysql.connector import connection

BASE_DIR = os.path.abspath(os.path.dirname(__file__))

UPLOAD_FOLDER = os.path.join(BASE_DIR, 'static', 'uploads')
ALLOWED_EXTENSIONS = {'png', 'jpeg', 'jpg', 'gif', 'webp'}
MAX_CONTENT_LENGTH = 6 * 1024 * 1024

os.makedirs(UPLOAD_FOLDER, exist_ok=True)

app = Flask(__name__)
app.config['SESSION_TYPE'] = 'filesystem'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = MAX_CONTENT_LENGTH

app.secret_key = os.environ["SECRET_KEY"]

bcrypt = Bcrypt(app)
Session(app)

# Razorpay credentials are read from environment variables.
client = razorpay.Client(
    auth=(
        os.environ["RAZORPAY_KEY_ID"],
        os.environ["RAZORPAY_KEY_SECRET"]
    )
)

# Database connection uses environment variables.
# This still requires a reachable MySQL server.
mydb = connection.MySQLConnection(
    host=os.environ["DB_HOST"],
    port=int(os.getenv("DB_PORT", "3306")),
    user=os.environ["DB_USER"],
    password=os.environ["DB_PASSWORD"],
    database=os.environ["DB_NAME"]
)


# Home page
@app.route('/')
def welcome():
    return render_template('welcome.html')

#BookNowPrompt
@app.route('/booknowprompt')
def booknowprompt():
    if 'user_id' not in session:  # check login
        flash("Please login or sign up first!", "warning")
        return redirect(url_for('user_login'))
    return render_template('user_login.html')

#User Signup page
@app.route('/user_signup',methods=['GET','POST'])
def user_signup():
    if request.method=='POST':
        user_name=request.form['name']
        user_email=request.form['email']
        user_phoneno=request.form['phoneno']
        user_address=request.form['address']
        user_password=request.form['password']
        user_agree=request.form['agree']
        # Check if email exists 
        try:
            cursor=mydb.cursor(buffered=True)
            cursor.execute('select count(*) from users where user_email=%s',[user_email,])
            email_count=cursor.fetchone()[0]  #(1,) or(0,)
            cursor.close()
        except Exception as e:
            print(e)
            flash('Database Error - Details could not stored in database')
            return redirect(url_for('user_signup'))
        else:
            if email_count==0:
                gotp=genotp()
                userdata={'user_name':user_name,'user_email':user_email,'user_phoneno':user_phoneno,'user_address':user_address,'user_password':user_password,'user_agree':user_agree,'server_otp':gotp}
                subject='User Verification for makeup Application'
                body=f'Use the given otp for Verification: {gotp}'
                send_mail(to=user_email,subject=subject,body=body)
                flash(f'otp has been sent successfully to {user_email}')
                return redirect(url_for('user_otpverify',serverdata=endata(userdata)))
            elif email_count==1:
                flash('User already existed')
                return redirect(url_for('user_signup'))
    return render_template('user_signup.html')
    
#OTP Verification
@app.route('/user_otpverify/<serverdata>',methods=['GET','POST'])
def user_otpverify(serverdata):
    try:
        data=dndata(serverdata)
    except Exception as e:
        print(e)
        flash('Could not verify user details')
        return redirect(url_for('user_otpverify'))
    else:
        if request.method=='POST':
            user_otp=request.form['otp']
            if data['server_otp']==user_otp:
                # Hash password
                hash_password=generate_password_hash(data['user_password'])
                print(hash_password)
                # Insert user into DB with is_verified = 1
                try:
                    cursor=mydb.cursor(buffered=True)
                    cursor.execute('insert into users(user_id,user_name,user_email,user_phoneno,user_password,user_address,user_agree,is_verified) values(uuid_to_bin(uuid()),%s,%s,%s,%s,%s,%s,1)',[data['user_name'],data['user_email'],data['user_phoneno'],hash_password,data['user_address'],data['user_agree']])
                    mydb.commit()
                    cursor.close()
                except Exception as e:
                    print(e)
                    flash('could not store user details')
                    return redirect(url_for('user_otpverify',serverdata=serverdata))
                else:
                    flash("Account verified and created successfully! Please login.")
                    return redirect(url_for('user_login'))
            else:
                flash('Invalid OTP')
    return render_template('otpverify.html')

#User Login route
@app.route('/user_login', methods=['GET','POST'])
def user_login():
    if request.method == 'POST':
        login_user_email = request.form['email']
        login_user_password = request.form['password']

        try:
            cursor = mydb.cursor(dictionary=True)
            cursor.execute('SELECT * FROM users WHERE user_email=%s', [login_user_email])
            user = cursor.fetchone()
            cursor.close()
        except Exception as e:
            print(e)
            flash('Could not verify the email')
            return redirect(url_for('user_login'))

        if user:
            if user['is_verified'] != 1:
                flash('Email is not verified. Please check your inbox for OTP.')
                return redirect(url_for('user_login'))

            if check_password_hash(user['user_password'], login_user_password):
                session['user'] = user['user_email']
                session['user_id'] = user['user_id']
                flash("Login successful!")
                return redirect(url_for('user_dashboard'))
            else:
                flash('Invalid password')
                return redirect(url_for('user_login'))
        else:
            flash('No user found')
            return redirect(url_for('user_login'))

    return render_template('user_login.html')
#Forgot Password
@app.route('/user_forgot_password',methods=['GET','POST'])
def user_forgot_password():
    if request.method=='POST':
        user_email=request.form['Email']
        try:
            cursor=mydb.cursor(buffered=True)
            cursor.execute('select count(*) from users where user_email=%s',[user_email])
            email_count=cursor.fetchone()[0]#(1,) or (0,)
            cursor.close()
        except Exception as e:
            print(e)
            flash("could not verify the email")
            return redirect(url_for('user_signup'))
        else:
            if email_count==1:
                subject='Reset Link for Makeup Application'
                body=f'Use the given link for password update {url_for('user_new_password',data=endata(user_email),_external=True)}'
                send_mail(to=user_email,subject=subject,body=body)
                flash('Reset link is sent to email')
                return redirect(url_for('user_forgot_password'))
            elif email_count==0:
                flash('No user Found')
    return render_template('user_forgot_password.html')
#Update New Password

@app.route('/user_new_password/<data>', methods=['GET', 'POST'])
def user_new_password(data):
    try:
        user_email = dndata(data)  # decode email from token
    except:
        flash('Invalid or expired link', 'danger')
        return redirect(url_for('user_forgot_password'))

    if request.method == 'POST':
        data = request.get_json()
        if not data or 'new_password' not in data:
            return jsonify({'message': 'No password provided'}), 400

        new_password = data['new_password']
        hashed_password = generate_password_hash(new_password)

        cursor = mydb.cursor()
        cursor.execute(
            "UPDATE users SET user_password=%s WHERE user_email=%s",
            (hashed_password, user_email)
        )
        mydb.commit()
        cursor.close()

        return jsonify({'message': 'Password updated successfully!'})

    # For GET request, render the reset form
    return render_template('user_new_password.html', data=data)

@app.route('/admin_login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        admin_email = request.form['email']
        admin_password = request.form['password']
        cursor = mydb.cursor(buffered=True)
        cursor.execute("SELECT admin_password FROM admin WHERE admin_email=%s", [admin_email])
        data = cursor.fetchone()
        cursor.close()

        if data:
            stored_password = data[0]  # hashed password from DB
            if check_password_hash(stored_password, admin_password):
                session['admin'] = admin_email
                flash('Login successful', 'success')
                return redirect(url_for('admin_dashboard'))
            else:
                flash('Invalid password', 'danger')
        else:
            flash('Admin not found', 'danger')

    return render_template('admin_login.html')

@app.route('/admin_forgot_password', methods=['GET', 'POST'])
def admin_forgot_password():
    if request.method == 'POST':
        admin_email = request.form['Email']
        cursor = mydb.cursor(buffered=True)
        cursor.execute("SELECT count(*) FROM admin WHERE admin_email=%s", [admin_email])
        exists = cursor.fetchone()[0]
        cursor.close()

        if exists:
            token = endata(admin_email)  # your encoding function

            reset_link = url_for('admin_new_password', token=token, _external=True)

            send_mail(
                to=admin_email,
                subject='Admin Password Reset',
                body=f'Click the link to reset password: {reset_link}'
            )

            flash('Reset link sent to your email', 'success')
        else:
            flash('Email not found', 'danger')

    return render_template('admin_forgot_password.html')


@app.route('/admin_new_password/<token>', methods=['POST', 'GET'])
def admin_new_password(token):
    try:
        admin_email = dndata(token)  # decode the token to get email
    except Exception as e:
        if request.is_json:
            return jsonify({'message': 'Invalid or expired link'}), 400
        flash('Invalid or expired link', 'danger')
        return redirect(url_for('admin_forgot_password'))

    if request.method == 'POST':
        # Handle AJAX JSON request
        try:
            data = request.get_json()
            new_password = data['new_password']
        except:
            return jsonify({'message': 'Password not provided'}), 400

        if len(new_password) < 6:
            return jsonify({'message': 'Password must be at least 6 characters'}), 400

        hashed_password = generate_password_hash(new_password)

        cursor = mydb.cursor()
        cursor.execute(
            "UPDATE admin SET admin_password=%s WHERE admin_email=%s",
            (hashed_password, admin_email)
        )
        mydb.commit()
        cursor.close()

        return jsonify({'message': 'Password updated successfully!'})

    # GET request — render HTML page
    return render_template('admin_new_password.html', token=token)

@app.route('/admin_dashboard')
def admin_dashboard():
    cursor = mydb.cursor(dictionary=True)

    # 1️⃣ Pending appointments (for Pending Appointments card)
    cursor.execute("""
        SELECT b.*, s.service_name 
        FROM bookings b 
        JOIN services s ON b.service_id = s.service_id 
        WHERE b.status='Pending' 
        ORDER BY b.created_at DESC
    """)
    appointments = cursor.fetchall()

    # 2️⃣ Recent bookings (all statuses, for Recent Bookings table)
    cursor.execute("""
        SELECT b.*, s.service_name 
        FROM bookings b 
        JOIN services s ON b.service_id = s.service_id 
        ORDER BY b.created_at DESC
        LIMIT 10
    """)
    
    recent_bookings = cursor.fetchall()
    cursor.execute(""" select count(*) from users """)
    total_users = cursor.fetchone()

    cursor.execute('select count(*) from bookings')
    # Total bookings
    total_bookings = cursor.fetchone()

    cursor.execute('select count(*) from bookings where status="pending"')
    # Pending appointments
    pending_appointments = cursor.fetchone()

    cursor.execute('select count(*) from bookings where status="approved"')
    # Completed appointments
    approved_appointments = cursor.fetchone()

    cursor.close()

    return render_template(
        'admin_dashboard.html', 
        appointments=appointments,
        recent_bookings=recent_bookings,
        total_users=total_users,
        total_bookings=total_bookings,
        pending_appointments=pending_appointments,
        approved_appointments=approved_appointments
    )

@app.route('/delete_booking/<int:booking_id>', methods=['POST'])
def delete_booking(booking_id):
    cursor = mydb.cursor()
    try:
        cursor.execute("DELETE FROM bookings WHERE booking_id = %s", (booking_id,))
        mydb.commit()
        flash("Booking deleted successfully!", "success")
    except Exception as e:
        print("Error deleting booking:", e)
        flash("Could not delete booking.", "danger")
    finally:
        cursor.close()
    return redirect(url_for('admin_dashboard'))
@app.route('/admin_services', methods=['GET', 'POST'])
def admin_services():
    if request.method == 'POST':
        # Add new service
        name = request.form['service_name']
        description = request.form['description']
        price = request.form['price']
        duration = request.form['duration']
        category = request.form.get('category', '')
        
        # Handle image upload
        image_file = request.files.get('image')
        filename = None
        if image_file and image_file.filename != '':
            filename = secure_filename(image_file.filename)
            print("Saving file:",filename)
            image_file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        cursor = mydb.cursor()
        sql = "INSERT INTO services (service_name, description, price, duration, category, image, created_at) VALUES (%s,%s,%s,%s,%s,%s,NOW())"
        cursor.execute(sql, (name, description, price, duration, category, filename))
        mydb.commit()
        cursor.close()
        flash("Service added successfully!", "success")
        return redirect(url_for('admin_services'))
    cursor=mydb.cursor(dictionary=True)
    cursor.execute("SELECT * FROM services ORDER BY created_at DESC")
    services = cursor.fetchall()
    cursor.close()
    return render_template('admin_services.html', services=services)

# Edit Service
@app.route('/edit_service/<int:service_id>', methods=['GET', 'POST'])
def edit_service(service_id):
    cursor = mydb.cursor(dictionary=True, buffered=True)
    cursor.execute("SELECT * FROM services WHERE service_id=%s", (service_id,))
    service = cursor.fetchone()
    if request.method == 'POST':
        name = request.form['service_name']
        description = request.form['description']
        price = request.form['price']
        duration = request.form['duration']
        category = request.form.get('category', '')
        image_file = request.files.get('image')
        filename = service['image']  # keep old image
        if image_file and image_file.filename != '':
            filename = secure_filename(image_file.filename)
            image_file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        cursor.execute("""
            UPDATE services
            SET service_name=%s, description=%s, price=%s, duration=%s, category=%s, image=%s
            WHERE service_id=%s
        """, (name, description, price, duration, category, filename, service_id))
        mydb.commit()
        cursor.close()
        flash("Service updated successfully!", "success")
        return redirect(url_for('admin_services'))
    cursor.close()
    return render_template('admin_edit_services.html', service=service)

# Delete Service
@app.route('/delete_service/<int:service_id>')
def delete_service(service_id):
    cursor = mydb.cursor(dictionary=True, buffered=True)
    cursor.execute("SELECT image FROM services WHERE service_id=%s", (service_id,))
    service = cursor.fetchone()
    if service and service['image']:
        try:
            os.remove(os.path.join(app.config['UPLOAD_FOLDER'], service['image']))
        except FileNotFoundError:
            pass
    cursor.execute("DELETE FROM services WHERE service_id=%s", (service_id,))
    mydb.commit()
    cursor.close()
    flash("Service deleted successfully!", "success")
    return redirect(url_for('admin_services'))

@app.route('/admin_bookings')
def admin_bookings():
    cursor = mydb.cursor(dictionary=True)
    query = """
    SELECT b.*, s.service_name 
    FROM bookings b
    JOIN services s ON b.service_id = s.service_id
    ORDER BY b.created_at DESC
    """
    cursor.execute(query)
    bookings = cursor.fetchall()
    cursor.close()
    return render_template('admin_bookings.html', bookings=bookings)
@app.route('/approve_appointment/<int:booking_id>', methods=['POST'])
def approve_appointment(booking_id):
    cursor = mydb.cursor(dictionary=True)
    
    # Fetch appointment
    cursor.execute("""
        SELECT b.*, s.service_name 
        FROM bookings b 
        JOIN services s ON b.service_id = s.service_id 
        WHERE b.booking_id = %s
    """, (booking_id,))
    
    appointment = cursor.fetchone()
    if not appointment:
        flash("Appointment not found", "danger")
        return redirect(url_for('admin_dashboard'))
    
    # Update status
    cursor.execute("UPDATE bookings SET status='Approved' WHERE booking_id=%s", (booking_id,))
    mydb.commit()
    cursor.close()
    
    # Send email to user
    send_user_appointment_email(appointment)
    
    flash("Appointment approved and user notified.", "success")
    return redirect(url_for('admin_dashboard'))

@app.route('/cancel_appointment/<int:booking_id>', methods=['POST'])
def cancel_appointment(booking_id):
    cursor = mydb.cursor(dictionary=True)
    
    # Fetch appointment details
    cursor.execute("""
        SELECT b.*, s.service_name 
        FROM bookings b
        JOIN services s ON b.service_id = s.service_id
        WHERE b.booking_id = %s
    """, (booking_id,))
    
    appointment = cursor.fetchone()
    if not appointment:
        flash("Appointment not found", "danger")
        return redirect(url_for('admin_dashboard'))
    
    # Update status to Cancelled
    cursor.execute("UPDATE bookings SET status='Cancelled' WHERE booking_id=%s", (booking_id,))
    mydb.commit()
    cursor.close()
    
    # Send email to user about cancellation
    send_user_cancel_email(appointment)
    
    flash("Appointment cancelled and user notified.", "warning")
    return redirect(url_for('admin_dashboard'))

@app.route('/complete_booking/<int:booking_id>', methods=['POST'])
def complete_booking(booking_id):
    cursor = mydb.cursor()
    
    cursor.execute("UPDATE bookings SET status='Completed' WHERE booking_id=%s", (booking_id,))
    mydb.commit()
    cursor.close()

    flash("Booking marked as completed", "success")
    return redirect(url_for('admin_bookings'))

# Admin Gallery Page

@app.route('/admin_gallery')
def admin_gallery():
    cursor = mydb.cursor(dictionary=True)
    cursor.execute("SELECT * FROM gallery ORDER BY uploaded_at DESC")
    gallery = cursor.fetchall()
    cursor.close()

    return render_template('admin_gallery.html', gallery=gallery)

# Add new image
@app.route('/admin_add_image', methods=['POST'])
def admin_add_image():
    title = request.form['image_title']
    category = request.form.get('image_category', 'General')
    file = request.files['image_file']

    if file and file.filename != "":
        from werkzeug.utils import secure_filename
        import os

        filename = secure_filename(file.filename)

        # Save file to static/uploads
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)
        cursor = mydb.cursor()
        cursor.execute(
            "INSERT INTO gallery (title, image_url, category, uploaded_at) VALUES (%s, %s, %s, NOW())",
            (title, filename, category)
        )
        mydb.commit()
        cursor.close()
        flash('Image uploaded successfully!', 'success')
    else:
        flash('No file selected', 'danger')

    return redirect(url_for('admin_gallery'))

# Delete image

@app.route('/admin_delete_image/<int:image_id>')
def admin_delete_image(image_id):
    cursor = mydb.cursor(dictionary=True)

    cursor.execute("SELECT image_url FROM gallery WHERE image_id = %s", (image_id,))
    row = cursor.fetchone()
    if row:
        file_path = os.path.join('static', row['image_url'])
        if os.path.exists(file_path):
            os.remove(file_path)

    cursor.execute("DELETE FROM gallery WHERE image_id = %s", (image_id,))
    mydb.commit()
    cursor.close()

    flash('Image deleted successfully!', 'success')
    return redirect(url_for('admin_gallery'))

@app.route('/admin_logout')
def admin_logout():
    # Remove admin session if exists
    if 'admin_email' in session:
        session.pop('admin_email', None)
        flash('Admin logged out successfully.', 'success')
    return redirect(url_for('admin_login'))

@app.route('/user_dashboard')
def user_dashboard():
    return render_template('user_dashboard.html')


@app.route('/user_services')
def user_services():
    try:
        cursor = mydb.cursor(dictionary=True)
        # Fetch all services added by admin
        query = """
            SELECT service_id, service_name, description, price, category, image 
            FROM services
            ORDER BY service_id DESC
        """
        cursor.execute(query)
        services = cursor.fetchall()
        cursor.close()
    except Exception as e:
        print("Error fetching services:", e)
        # Send empty list instead of breaking page
        return render_template("user_services.html", services=[])
    else:
        return render_template("user_services.html", services=services)

@app.route('/user_gallery')
def user_gallery():
    cursor = mydb.cursor(dictionary=True)
    # Fetch all images from Gallery table, newest first
    cursor.execute("SELECT * FROM Gallery ORDER BY uploaded_at DESC")
    images = cursor.fetchall()  # images will have id, image_name, image_path, uploaded_at
    return render_template("user_gallery.html", images=images)

@app.route('/user_booking', methods=['POST', 'GET'])
def user_booking():
    if not session.get('user'):
        flash("Please login first")
        return redirect(url_for('user_login'))

    # Load services for GET request
    cursor = mydb.cursor(dictionary=True)
    cursor.execute("SELECT * FROM services")
    services = cursor.fetchall()
    cursor.close()

    if request.method == 'POST':
        # Get form data
        customer_name = request.form['customer_name']
        customer_email = request.form['customer_email']
        customer_phone = request.form['customer_phone']
        service_id = request.form['service_id']
        booking_date = request.form['booking_date']
        booking_time = request.form['booking_time']
        venue = request.form['venue']
        notes = request.form['notes']
        payment_method = request.form['payment_method']

        # Fetch service details
        cursor = mydb.cursor()
        cursor.execute("SELECT service_name, price FROM services WHERE service_id=%s", (service_id,))
        service = cursor.fetchone()
        service_name = service[0]
        service_price = service[1]
        cursor.close()

        # If advance payment
        if payment_method == "advance":
            # Calculate 20% advance
            advance_amount = round(float(service_price) * 0.2, 2)
            order_amount = int(advance_amount * 100)  # Razorpay requires amount in paise
            receipt = f"receipt_{session.get('user_id')}"[:40]
            print("Receipt length:", len(receipt), receipt)
            try:
                # Create Razorpay order
                order = client.order.create({
                    "amount": order_amount,
                    "currency": "INR",
                    "receipt": receipt
                })
                print('order',order)

                # Render payment page
                return render_template('booking_payment.html', order=order,
                                       customer_name=customer_name,
                                       customer_email=customer_email,
                                       customer_phone=customer_phone,
                                       service_id=service_id,
                                       service_name=service_name,
                                       booking_date=booking_date,
                                       booking_time=booking_time,
                                       venue=venue,
                                       notes=notes,
                                       advance_amount=advance_amount)

            except Exception as e:
                print("Razorpay Error:", e)
                flash("Could not process payment")
                return redirect(url_for('user_booking'))

        else:
            # Pay Later flow
            advance_amount = 0
            user_id = session.get('user_id')  # must be set at login
            total = float(service_price)
            remaining = total - advance_amount

            cursor = mydb.cursor()
            cursor.execute("""
                INSERT INTO bookings
                (user_id, customer_name, customer_email, customer_phone, service_id,
                 booking_date, booking_time, venue, notes,
                 total_price, advance_amount, remaining_amount, status, payment_method)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
            """, (
                user_id,
                customer_name,
                customer_email,
                customer_phone,
                service_id,
                booking_date,
                booking_time,
                venue,
                notes,
                total,
                advance_amount,
                remaining,
                'Pending',
                'later'
            ))
            mydb.commit()
            cursor.close()
            flash("Booking saved. Pay later at venue.")
            return redirect(url_for('user_dashboard'))

    # GET request → render booking form
    return render_template('user_booking.html', services=services)

@app.route('/booking_payment_success', methods=['POST'])
def booking_payment_success():
    data = request.get_json()
    print("DATA RECEIVED:", data)
    print('razorpay_order_id',data.get('razorpay_order_id'))
    print('razorpay_payment_id',data.get('razorpay_payment_id'))
    print('razorpay_signature',data.get('razorpay_signature'))
    print('data over')

    if not session.get('user_id'):
        return jsonify({"status": "fail", "message": "User not logged in"}), 401

    try:
        # Verify Razorpay payment signature
        client.utility.verify_payment_signature({
            'razorpay_order_id': str(data.get('razorpay_order_id')),
            'razorpay_payment_id': str(data.get('razorpay_payment_id')),
            'razorpay_signature': str(data.get('razorpay_signature'))
        })

        # Calculate amounts
        advance = float(data.get('advance_amount', 0))
        total = round(advance / 0.2, 2)
        remaining = round(total - advance, 2)

        # Insert booking
        user_id = session.get('user_id')
        cursor = mydb.cursor()
        cursor.execute("""
            INSERT INTO bookings
            (user_id, customer_name, customer_email, customer_phone, service_id,
            booking_date, booking_time, venue, notes,
            total_price, advance_amount, remaining_amount, status, payment_method)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
        """, (
            user_id,
            data.get('customer_name'),
            data.get('customer_email'),
            data.get('customer_phone'),
            int(data.get('service_id')),
            data.get('booking_date'),
            data.get('booking_time'),
            data.get('venue'),
            data.get('notes'),
            total,
            advance,
            remaining,
            'Pending',
            'advance'
        ))
        mydb.commit()

        # Get the last inserted booking_id
        booking_id = cursor.lastrowid
        cursor.execute("""
            INSERT INTO payments
            (booking_id, total_amount, amount_paid, remaining_amount, payment_method, payment_status, transaction_id)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
        """, (
            booking_id,
            total,
            advance,
            remaining,
            'advance',
            'paid',
            data.get('razorpay_payment_id')
        ))
        mydb.commit()
        cursor.close()

        return jsonify({"status": "ok", "message": "Booking & payment saved successfully!"})

    except razorpay.errors.SignatureVerificationError as e:
        print("SIGNATURE ERROR:", e)
        return jsonify({"status": "fail", "message": "Signature verification failed"}), 400

    except Exception as e:
        print("GENERAL ERROR:", e)
        return jsonify({"status": "fail", "message": "Server error"}), 500

# View Bookings Page
# -----------------------------
@app.route('/view_booking')
def view_booking():
    user_id = session.get('user_id')
    if not user_id:
        return redirect(url_for('user_login'))
    cursor=mydb.cursor()
    cursor.execute("SELECT * FROM bookings WHERE user_id=%s", (user_id,))
    bookings = cursor.fetchall()
    cursor.close()
    return render_template('view_booking.html', bookings=bookings)

# -----------------------------
# Cancel Booking
# -----------------------------
@app.route('/cancel_booking/<int:booking_id>', methods=['POST'])
def cancel_booking(booking_id):
    user_id = session.get('user_id')
    cursor=mydb.cursor()
    cursor.execute("SELECT status FROM bookings WHERE booking_id=%s AND user_id=%s", (booking_id, user_id))
    booking = cursor.fetchone()
    if not booking:
        flash("Booking not found!")
        return redirect(url_for('view_booking'))
        
    if booking['status'] == 'Pending':
        cursor.execute("DELETE FROM bookings WHERE booking_id=%s", (booking_id,))
        mydb.commit()
        flash("Booking cancelled successfully!")
    else:
        flash("Cannot cancel a booking that is already Successful.")
    cursor.close()
    return redirect(url_for('view_booking'))

# -----------------------------
# Update Booking Page
# -----------------------------
@app.route('/update_booking/<int:booking_id>', methods=['GET','POST'])
def update_booking(booking_id):
    user_id = session.get('user_id')
    cursor=mydb.cursor()
    if request.method == 'POST':
        new_date = request.form['booking_date']
        new_time = request.form['booking_time']
        new_venue = request.form['venue']
        new_notes = request.form['notes']
        cursor.execute("""
                UPDATE bookings
                SET booking_date=%s, booking_time=%s, venue=%s, notes=%s
                WHERE booking_id=%s AND user_id=%s
            """, (new_date, new_time, new_venue, new_notes, booking_id, user_id))
        mydb.commit()
        cursor.close()
        flash("Booking updated successfully!")
        return redirect(url_for('view_booking'))

        # GET request
    cursor.execute("SELECT * FROM bookings WHERE booking_id=%s AND user_id=%s", (booking_id, user_id))
    booking = cursor.fetchone()
    cursor.close()
    if not booking:
        flash("Booking not found!")
        return redirect(url_for('view_booking'))

    return render_template('update_booking.html', booking=booking)

@app.route('/about_us')
def about_us():
    return render_template('about_us.html')


@app.route('/contact', methods=['GET', 'POST'])
def contact():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        subject = request.form['subject']
        message = request.form['message']
        flash("Your message has been sent successfully! We will contact you soon.")
        return redirect(url_for('contact'))

    # Admin details to pass to template 
    admin_info = {
        "name": "Lakshmi Neppalli",
        "email": "lakshmineppalli1983@gmail.com",
        "phone": "+91 9394295467",
        "address": "0 line, 2nd Ln, near water tank, Srinagar, Satyaranayana Puram, Vijayawada, Andhra Pradesh 520004"
    }

    return render_template('contact.html', admin=admin_info)

# LOGOUT ROUTE
@app.route('/user_logout')
def user_logout():
    session.clear()
    return redirect(url_for('user_login'))  # Redirect to login page

if __name__ == "__main__":
    app.run(debug=True, use_reloader=True)
