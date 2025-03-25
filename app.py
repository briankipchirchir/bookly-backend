
from flask import Flask, request, jsonify,make_response,send_file,after_this_request
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import (
    JWTManager, create_access_token, jwt_required, get_jwt_identity
)
from flask_jwt_extended.exceptions import NoAuthorizationError, JWTDecodeError, InvalidHeaderError

from flask_cors import CORS,cross_origin
from flask_migrate import Migrate
from models import db, User, bcrypt, ReadingHistory, Book,Favorite,Topic,Reply
from flask_socketio import SocketIO, send, emit, join_room, leave_room
import re
from datetime import datetime
from reportlab.pdfgen import canvas
import os
from reportlab.lib.pagesizes import letter 
from datetime import timedelta



app = Flask(__name__)

# Enable CORS for frontend

CORS(app, supports_credentials=True)  # Apply CORS globally



# Database Configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///bookly.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = 'supersecretkey'  # Change this in production
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(days=7)

# Initialize Database & JWT
db.init_app(app)
migrate = Migrate(app, db)
jwt = JWTManager(app)

# --------- HELPER FUNCTIONS ---------
def is_valid_email(email):
    """Validate email format (must end with @gmail.com)"""
    return bool(re.match(r'^[a-zA-Z0-9._%+-]+@gmail\.com$', email))

# --------- AUTH ROUTES ---------

@app.after_request
def add_cors_headers(response):
    response.headers["Access-Control-Allow-Origin"] = "http://localhost:5173"
    response.headers["Access-Control-Allow-Credentials"] = "true"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
    return response


# Signup Route
@app.route('/signup', methods=['POST'])
def signup():
    if not request.is_json:
        return jsonify({'error': 'Invalid request format. JSON expected'}), 400

    data = request.get_json()
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')

    # Validate input fields
    if not username or not email or not password:
        return jsonify({'error': 'All fields are required'}), 400

    # Validate email format
    if not is_valid_email(email):
        return jsonify({'error': 'Invalid email format. mOnly @gmail.com emails are allowed.'}), 400

    # Check if email already exists
    if User.query.filter_by(email=email).first():
        return jsonify({'error': 'Email already exists'}), 400

    # Create new user
    new_user = User(username=username, email=email,joined_at=datetime.utcnow())
    new_user.set_password(password)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({'message': 'User created successfully',
                    'joined_at': new_user.joined_at.strftime('%Y-%m-%d')}), 201

# Login Route
@app.route('/login', methods=['POST'])
def login():
    if not request.is_json:
        return jsonify({'error': 'Invalid request format. JSON expected'}), 400

    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    user = User.query.filter_by(email=email).first()
    if not user or not user.check_password(password):
        return jsonify({'error': 'Invalid email or password'}), 401

    access_token = create_access_token(identity=str(user.id))  # Ensure JWT identity is a string

    return jsonify({'token': access_token, 'user': {'id': user.id, 'username': user.username, 'email': user.email,'joined_at':user.joined_at}})

# --------- PROTECTED ROUTES ---------



# --------- FAVORITE BOOKS ROUTES ---------
@app.route('/favorites', methods=['POST'])  # ✅ Ensure it's a POST request
@jwt_required()
def add_to_favorites():
    user_id = get_jwt_identity()  # Get logged-in user ID
    data = request.get_json()

    book_id = data.get("book_id")
    title = data.get("title")
    author = data.get("author")
    description = data.get("description")  # ✅ Ensure description is included
    image_url = data.get("image_url")

    if not all([book_id, title, author, description]):  
        return jsonify({"error": "Missing book details"}), 400

    # Check if the book exists in the database
    book = Book.query.get(book_id)
    if not book:
        book = Book(
            id=book_id, 
            title=title, 
            author=author, 
            description=description, 
            image_url=image_url
        )
        db.session.add(book)
        db.session.commit()

    # Check if the user already favorited the book
    favorite = Favorite.query.filter_by(user_id=user_id, book_id=book.id).first()
    if favorite:
        return jsonify({"message": "Book is already in favorites"}), 400

    # Add book to favorites
    new_favorite = Favorite(user_id=user_id, book_id=book.id)
    db.session.add(new_favorite)
    db.session.commit()

    return jsonify({
        "message": "✅ Book added to favorites!",
        "book": {
            "id": book.id,
            "title": book.title,
            "author": book.author,
            "description": book.description,  
            "image_url": book.image_url
        }
    }), 201


@app.route("/favorites", methods=["GET"])
@cross_origin(origins="http://localhost:5173")
@jwt_required()
def get_favorites():
    user_id = get_jwt_identity()
    favorites = Favorite.query.filter_by(user_id=user_id).all()
    
    return jsonify([{
        "id": fav.book.id,
        "title": fav.book.title,
        "author": fav.book.author,
        "image_url": fav.book.image_url,
        "description": fav.book.description
    } for fav in favorites])



@app.route("/favorites/<int:book_id>", methods=["DELETE"])
@jwt_required()
def remove_favorite(book_id):
    """Remove a book from favorites"""
    user_id = get_jwt_identity()
    user = User.query.get(user_id)

    if not user:
        return jsonify({"error": "User not found"}), 404

    # Find the favorite entry
    favorite_entry = Favorite.query.filter_by(user_id=user.id, book_id=book_id).first()

    if not favorite_entry:
        return jsonify({"error": "Book not found in favorites"}), 404

    try:
        db.session.delete(favorite_entry)
        db.session.commit()
        return jsonify({"message": "Book removed from favorites"}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": "An error occurred while removing the book"}), 500

@app.route("/history", methods=["POST"])
@jwt_required()
def add_to_history():
    try:
        user_id = get_jwt_identity()
        print("🔍 User ID from JWT:", user_id)  # Debugging

        data = request.json
        book_id = data.get("book_id")

        if not book_id:
            return jsonify({"error": "Book ID is required"}), 400

        # Prevent duplicates
        existing_entry = ReadingHistory.query.filter_by(user_id=user_id, book_id=book_id).first()
        if existing_entry:
            return jsonify({"error": "Book is already in reading history"}), 400

        history_entry = ReadingHistory(user_id=user_id, book_id=book_id)
        db.session.add(history_entry)
        db.session.commit()

        return jsonify({"message": "Book added to reading history"}), 201

    except NoAuthorizationError:
        print("❌ JWT ERROR: No authorization token found")
        return jsonify({"error": "No authorization token"}), 401

    except JWTDecodeError:
        print("❌ JWT ERROR: Invalid or expired token")
        return jsonify({"error": "Invalid or expired token"}), 401

    except InvalidHeaderError:
        print("❌ JWT ERROR: Invalid token header")
        return jsonify({"error": "Invalid token header"}), 401

@app.route("/history", methods=["GET"])
@jwt_required()
def get_history():
    """Retrieve user's reading history"""
    print("📌 Request Headers:", request.headers)  # Log headers

    user_id = get_jwt_identity()
    print(f"🔍 User ID from JWT: {user_id}")  

    if not user_id:
        return jsonify({"error": "Unauthorized - Invalid token"}), 401

    history = ReadingHistory.query.filter_by(user_id=user_id).all()
    return jsonify([{
        "book_id": h.book.id if h.book else None,
        "title": h.book.title if h.book else "Unknown",
        "author": h.book.author if h.book else "Unknown",
        "image_url": h.book.image_url if h.book else None,
        "timestamp": h.timestamp
    } for h in history])

# Initialize Socket.IO
socketio = SocketIO(app, cors_allowed_origins="http://localhost:5173", async_mode="threading")

# Active users
active_users = set()

# --------- DISCUSSION PANEL (Socket.IO) ---------

@socketio.on('connect')
def handle_connect():
    print("A user connected")

@socketio.on('disconnect')
def handle_disconnect():
    print("A user disconnected")

@socketio.on('join')
def handle_join(data):
    """Handle a user joining a discussion room"""
    username = data.get('username', 'Unknown')
    room = data.get('room', 'general')  # Default room is 'general'

    join_room(room)
    active_users.add(username)
    print(f"{username} joined {room}")

    # Notify all users in the room
    emit('user_joined', {'message': f"{username} has joined the room!"}, room=room, broadcast=True)

@socketio.on('leave')
def handle_leave(data):
    """Handle a user leaving a discussion room"""
    username = data.get('username', 'Unknown')
    room = data.get('room', 'general')

    leave_room(room)
    active_users.discard(username)
    print(f"{username} left {room}")

    # Notify all users in the room
    emit('user_left', {'message': f"{username} has left the room!"}, room=room, broadcast=True)

@socketio.on('message')
def handle_message(data):
    """Handle incoming messages"""
    username = data.get('username', 'Unknown')
    room = data.get('room', 'general')
    message = data.get('message', '')

    print(f"Message from {username} in {room}: {message}")

    # Broadcast message to all users in the room
    emit('new_message', {'username': username, 'message': message}, room=room)

@app.route("/admin/users", methods=["GET"])
def get_all_users():
    """Retrieve all users (Open to Everyone)"""
    users = User.query.all()
    return jsonify([{
        "id": user.id,
        "username": user.username,
        "email": user.email,
        "favorite_books": [fav.book.title for fav in user.favorites] if user.favorites else [],
         "reading_history": [history.book.title for history in user.reading_history if history and history.book] if user.reading_history else [],


        "joined_at": user.joined_at.strftime('%Y-%m-%d') if user.joined_at else "N/A"

    } for user in users])


@app.route("/admin/users/<int:user_id>", methods=["DELETE"])
def remove_user(user_id):
    """Delete a user (Open to Everyone - Not Recommended)"""
    user = User.query.get(user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404

    db.session.delete(user)
    db.session.commit()
    return jsonify({"message": "User deleted successfully"}), 200


@app.route("/admin/reports", methods=["GET"])
def generate_reports():
    """Generate a detailed user activity report and return a PDF"""

    # Fetch all users with their details
    users = User.query.all()

    # Define the PDF file path
    pdf_path = "detailed_user_report.pdf"
    
    # Create PDF
    c = canvas.Canvas(pdf_path, pagesize=letter)
    width, height = letter
    y_position = height - 50  # Start position

    # Report Title
    c.setFont("Helvetica-Bold", 16)
    c.drawString(180, y_position, "Bookly User Activity Report")
    y_position -= 30
    c.setFont("Helvetica", 12)
    c.drawString(50, y_position, f"Generated on: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')}")
    y_position -= 30

    # Summary Section
    total_users = len(users)
    total_books_read = sum(len(user.reading_history) for user in users)
    total_favorites = sum(len(user.favorites) for user in users)

    c.setFont("Helvetica-Bold", 12)
    c.drawString(50, y_position, "Report Summary:")
    y_position -= 20
    c.setFont("Helvetica", 10)
    c.drawString(70, y_position, f"Total Users: {total_users}")
    y_position -= 15
    c.drawString(70, y_position, f"Total Books Read: {total_books_read}")
    y_position -= 15
    c.drawString(70, y_position, f"Total Books Favorited: {total_favorites}")
    y_position -= 30

    # Loop through each user and add details
    for user in users:
        c.setFont("Helvetica-Bold", 12)
        c.drawString(50, y_position, f"User: {user.username} (ID: {user.id})")
        y_position -= 20
        c.setFont("Helvetica", 10)
        c.drawString(70, y_position, f"Email: {user.email}")
        y_position -= 15
        joined_at = user.joined_at.strftime('%Y-%m-%d') if user.joined_at else "N/A"
        c.drawString(70, y_position, f"Joined: {joined_at}")

        y_position -= 20

        # User's Favorite Books
        favorite_books = [fav.book.title for fav in user.favorites]
        if favorite_books:
            c.setFont("Helvetica-Bold", 11)
            c.drawString(70, y_position, "Favorite Books:")
            y_position -= 15
            c.setFont("Helvetica", 10)
            for book in favorite_books:
                c.drawString(90, y_position, f"- {book}")
                y_position -= 15
        else:
            c.drawString(70, y_position, "No Favorite Books")
            y_position -= 15

        # User's Reading History
        if user.reading_history:
            c.setFont("Helvetica-Bold", 11)
            c.drawString(70, y_position, "Reading History:")
            y_position -= 15
            c.setFont("Helvetica", 10)
            for record in user.reading_history:
                book_title = record.book.title if record.book else "Unknown"
                read_date = record.timestamp.strftime('%Y-%m-%d %H:%M') if record.timestamp else "Unknown"
                c.drawString(90, y_position, f"- {book_title} (Read on: {read_date})")
                y_position -= 15
        else:
            c.drawString(70, y_position, "No Reading History")
            y_position -= 15

        # Add spacing between users
        y_position -= 30
        if y_position < 50:
            c.showPage()
            y_position = height - 50

    c.save()  # Save the PDF

    # Check if PDF was created
    if not os.path.exists(pdf_path):
        return jsonify({"error": "PDF generation failed"}), 500

    # Send the generated PDF as a response
    return send_file(pdf_path, as_attachment=True, mimetype='application/pdf')

@app.route("/admin/reports/user/<int:user_id>", methods=["GET"])
def generate_single_user_report(user_id):
    """Generate a report for a specific user"""

    # Fetch user by ID
    user = User.query.get(user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404

    # Define absolute PDF file path
    pdf_path = os.path.join(os.getcwd(), f"user_report_{user_id}.pdf")

    # Create PDF
    c = canvas.Canvas(pdf_path, pagesize=letter)
    width, height = letter
    y_position = height - 50  # Start position

    # Report Title
    c.setFont("Helvetica-Bold", 16)
    c.drawString(180, y_position, "Activity Report")
    y_position -= 30
    c.setFont("Helvetica", 12)
    c.drawString(50, y_position, f"Generated on: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')}")
    y_position -= 30

    # User Details
    c.setFont("Helvetica-Bold", 12)
    c.drawString(50, y_position, f"User: {user.username} (ID: {user.id})")
    y_position -= 20
    c.setFont("Helvetica", 10)
    c.drawString(70, y_position, f"Email: {user.email}")
    y_position -= 15
    joined_at = user.joined_at.strftime('%Y-%m-%d') if user.joined_at else "N/A"
    c.drawString(70, y_position, f"Joined: {joined_at}")
    y_position -= 30

     # Count Favorite Books & Books Read
    num_favorites = len(user.favorites) if user.favorites else 0
    num_books_read = len(user.reading_history) if user.reading_history else 0
    c.drawString(70, y_position, f"Number of Favorite Books: {num_favorites}")
    y_position -= 15
    c.drawString(70, y_position, f"Number of Books Read: {num_books_read}")
    y_position -= 30  # Extra space before next section

    # User's Favorite Books
    favorite_books = [fav.book.title for fav in user.favorites] if user.favorites else []
    if favorite_books:
        c.setFont("Helvetica-Bold", 11)
        c.drawString(50, y_position, "Favorite Books:")
        y_position -= 20
        c.setFont("Helvetica", 10)
        for book in favorite_books:
            c.drawString(70, y_position, f"- {book}")
            y_position -= 15
    else:
        c.setFont("Helvetica-Italic", 10)
        c.drawString(50, y_position, "No Favorite Books")
        y_position -= 15

    y_position -= 10  # Space before next section

    # User's Reading History
    reading_history = user.reading_history if user.reading_history else []
    if reading_history:
        c.setFont("Helvetica-Bold", 11)
        c.drawString(50, y_position, "Reading History:")
        y_position -= 20
        c.setFont("Helvetica", 10)
        for record in reading_history:
            book_title = record.book.title if record.book else "Unknown Book"
            read_date = record.timestamp.strftime('%Y-%m-%d %H:%M') if record.timestamp else "Unknown Date"
            c.drawString(70, y_position, f"- {book_title} (Read on: {read_date})")
            y_position -= 15
    else:
        c.setFont("Helvetica-Italic", 10)
        c.drawString(50, y_position, "No Reading History")
        y_position -= 15

    c.save()  # Save PDF

    # Ensure PDF exists
    if not os.path.exists(pdf_path):
        print("PDF file not found!")  # Debugging log
        return jsonify({"error": "PDF generation failed"}), 500

    # Register cleanup after request
    @after_this_request
    def remove_file(response):
        try:
            os.remove(pdf_path)
        except Exception as e:
            print(f"Error deleting file: {e}")  # Debugging log
        return response

    # Send the generated PDF
    return send_file(pdf_path, mimetype="application/pdf", as_attachment=True, download_name=f"user_report_{user_id}.pdf")

@app.route('/leaderboard', methods=['GET'])
def get_leaderboard():
    users = User.query.all()
    leaderboard = [
        {
            "id": user.id,
            "username": user.username,
            "books_read": len(user.reading_history),
        }
        for user in users
    ]
    leaderboard.sort(key=lambda x: x["books_read"], reverse=True)
    return jsonify(leaderboard), 200


@app.route('/topics', methods=['POST'])
@jwt_required()
def create_topic():
    """Create a new topic and broadcast it to all users"""
    user_id = get_jwt_identity()
    data = request.get_json()

    title = data.get("title")
    content = data.get("content")

    if not title or not content:
        return jsonify({"error": "Title and content are required"}), 400

    new_topic = Topic(title=title, content=content, user_id=user_id)
    db.session.add(new_topic)
    db.session.commit()

    topic_data = new_topic.to_dict()  # Convert the topic to JSON format

    for key, value in topic_data.items():
       if isinstance(value, datetime):
        topic_data[key] = value.isoformat()

    # **Emit topic to all connected users**
    socketio.emit("new_topic", topic_data, to="general")  # Adjust "general" to your actual room name


    return jsonify({
        "message": "Topic created successfully",
        "topic": topic_data
    }), 201



@app.route('/topics', methods=['GET'])
def get_topics():
    """Retrieve all topics"""
    topics = Topic.query.all()
    topics_list = []

    for topic in topics:
        # Fetch the user associated with the topic
        user = User.query.get(topic.user_id)
        username = user.username if user else "Unknown"  # If user is not found, set to 'Unknown'

        topics_list.append({
            "id": topic.id,
            "title": topic.title,
            "content": topic.content,
            "user_id": topic.user_id,
            "username": username,  # Add username to the response
            "created_at": topic.created_at
        })

    return jsonify(topics_list)


@app.route('/topics/<int:topic_id>', methods=['GET'])
def get_topic(topic_id):
    topic = Topic.query.get(topic_id)
    if not topic:
        return jsonify({"error": "Topic not found"}), 404
    
    # Get the user object based on user_id
    user = User.query.get(topic.user_id)
    username = user.username if user else "Unknown"  # If user not found, return 'Unknown'

    return jsonify({
        "id": topic.id,
        "title": topic.title,
        "content": topic.content,
        "user_id": topic.user_id,
        "username": username,  # Include the username here
        "created_at": topic.created_at
    })



@app.route('/topics/<int:topic_id>', methods=['DELETE'])
@jwt_required()
def delete_topic(topic_id):
    """Delete a topic if the authenticated user is the owner"""
    user_id = get_jwt_identity()  # Get the logged-in user's ID

    # Debugging (you can remove this later)
    print(f"Authenticated user: {user_id} (type: {type(user_id)})")

    topic = Topic.query.filter_by(id=topic_id, user_id=user_id).first()  # Ensure topic belongs to user

    if not topic:
        return jsonify({"error": "Topic not found or unauthorized"}), 404  # Combined check

    db.session.delete(topic)
    db.session.commit()

    return jsonify({"message": "Topic deleted successfully"}), 200





@app.route('/topics/<int:topic_id>/replies', methods=['POST'])
@jwt_required()
def add_reply(topic_id):
    """Add a reply to a topic"""
    user_id = get_jwt_identity()
    data = request.get_json()

    content = data.get("content")

    if not content:
        return jsonify({"error": "Content is required"}), 400

    topic = Topic.query.get(topic_id)
    if not topic:
        return jsonify({"error": "Topic not found"}), 404

    user = User.query.get(user_id)  # Fetch user details
    if not user:
        return jsonify({"error": "User not found"}), 404

    new_reply = Reply(content=content, user_id=user_id, topic_id=topic_id)
    db.session.add(new_reply)
    db.session.commit()

    return jsonify({
        "message": "Reply added successfully",
        "reply": {
            "id": new_reply.id,
            "content": new_reply.content,
            "username": user.username,  # Include username
            "topic_id": new_reply.topic_id,
            "created_at": new_reply.created_at.strftime("%Y-%m-%d %H:%M:%S")  # Format timestamp
        }
    }), 201



@app.route('/topics/<int:topic_id>/replies', methods=['GET'])
def get_replies(topic_id):
    """Retrieve all replies for a topic"""
    replies = Reply.query.filter_by(topic_id=topic_id).all()

    return jsonify([{
        "id": reply.id,
        "content": reply.content,
        "username": reply.user.username,
        "topic_id": reply.topic_id,
        "created_at": reply.created_at
    } for reply in replies])


@app.route('/replies/<int:reply_id>', methods=['DELETE'])
@jwt_required()
def delete_reply(reply_id):
    """Delete a reply"""
    user_id = get_jwt_identity()
    print(f"JWT User ID: {user_id}")  # Debugging print

    reply = Reply.query.get(reply_id)
    
    if not reply:
        print("Reply not found")
        return jsonify({"error": "Reply not found"}), 404

    print(f"Reply belongs to User ID: {reply.user_id}")  # Debugging print

    if reply.user_id != int(user_id):  # Ensure correct type comparison
        print("Unauthorized: User ID does not match reply owner")
        return jsonify({"error": "Unauthorized"}), 403

    db.session.delete(reply)
    db.session.commit()

    print("Reply deleted successfully")
    return jsonify({"message": "Reply deleted successfully"}), 200














# Run the Flask app
if __name__ == "__main__":
    socketio.run(app, debug=True, allow_unsafe_werkzeug=True)
