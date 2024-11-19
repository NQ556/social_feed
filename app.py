from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from datetime import datetime, timedelta
import jwt
from functools import wraps
import os

# App
app = Flask(__name__)

# Database
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', '').replace("postgres://", "postgresql://")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Secret Key
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'default_secret_key')

# Extensions
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

# Database Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    avatarUrl = db.Column(db.Text, nullable=True)

class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    userId = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    updatedAt = db.Column(db.DateTime, default=datetime.utcnow)
    user = db.relationship('User', backref=db.backref('posts', lazy=True))

class PostLikes(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    postId = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=False)
    userId = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    updatedAt = db.Column(db.DateTime, default=datetime.utcnow)

class PostShares(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    postId = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=False)
    userId = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    updatedAt = db.Column(db.DateTime, default=datetime.utcnow)

class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    postId = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=False)
    userId = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    parentCommentId = db.Column(db.Integer, db.ForeignKey('comment.id'), nullable=True)
    content = db.Column(db.Text, nullable=False)
    updatedAt = db.Column(db.DateTime, default=datetime.utcnow)
    user = db.relationship('User', backref=db.backref('comments', lazy=True))

class CommentLikes(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    commentId = db.Column(db.Integer, db.ForeignKey('comment.id'), nullable=False)
    userId = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    updatedAt = db.Column(db.DateTime, default=datetime.utcnow)

# Token
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({"message": "Token is missing!"}), 403
        try:
            token = token.split(" ")[1]
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = User.query.get(data['user_id'])
        except Exception as e:
            return jsonify({"message": "Token is invalid!", "error": str(e)}), 403
        return f(current_user, *args, **kwargs)
    return decorated

# Routes
@app.route('/signUp', methods=['POST'])
def signUp():
    data = request.get_json()
    hashed_password = bcrypt.generate_password_hash(data['password']).decode('utf-8')
    
    new_user = User(email=data['email'], username=data['username'], password=hashed_password, avatarUrl=data['avatarUrl'])
    db.session.add(new_user)
    db.session.commit()

    # Generate token
    token = jwt.encode({
        "user_id": new_user.id,
        "exp": datetime.utcnow() + timedelta(hours=1)
    }, app.config['SECRET_KEY'], algorithm="HS256")
    
    return jsonify({
        "message": "User registered successfully!",
        "userId": new_user.id,
        "token": token
    }), 201


@app.route('/signIn', methods=['POST'])
def signIn():
    data = request.get_json()
    user = User.query.filter_by(email=data['email']).first()
    
    if user and bcrypt.check_password_hash(user.password, data['password']):
        # Generate token
        token = jwt.encode({
            "user_id": user.id,
            "exp": datetime.utcnow() + timedelta(hours=1)
        }, app.config['SECRET_KEY'], algorithm="HS256")
        
        return jsonify({"message": "Login successful!", "userId": user.id, "token": token}), 200
    
    return jsonify({"message": "Invalid email or password"}), 401

@app.route('/createPost', methods=['POST'])
@token_required
def createPost(current_user):
    data = request.get_json()
    new_post = Post(userId=current_user.id, content=data['content'])

    db.session.add(new_post)
    db.session.commit()

    return jsonify({
        "id": new_post.id,
        "userId": new_post.userId,
        "content": new_post.content,
        "updatedAt": new_post.updatedAt,
        "username": current_user.username,
        "email": current_user.email,
        "avatarUrl": current_user.avatarUrl,
        "likesCount": 0,
        "sharesCount": 0,
        "commentsCount": 0
    }), 201


@app.route('/getPosts', methods=['GET'])
@token_required
def getPosts(current_user):
    posts = Post.query.all()
    post_list = []

    for post in posts:
        likes_count = PostLikes.query.filter_by(postId=post.id).count()
        shares_count = PostShares.query.filter_by(postId=post.id).count()
        comments_count = Comment.query.filter_by(postId=post.id).count()
        
        post_list.append({
            "id": post.id,
            "userId": post.userId,
            "content": post.content,
            "updatedAt": post.updatedAt,
            "username": post.user.username,
            "email": post.user.email,
            "avatarUrl": post.user.avatarUrl,
            "likesCount": likes_count,
            "sharesCount": shares_count,
            "commentsCount": comments_count
        })
    
    return jsonify(post_list), 200

@app.route('/getPostComments', methods=['GET'])
@token_required
def getPostComments(current_user):
    comments = Comment.query.all()
    comment_list = []

    for comment in comments:
        likes_count = CommentLikes.query.filter_by(commentId=comment.id).count()
        comments_count = Comment.query.filter_by(parentCommentId=comment.id).count()
        
        comment_list.append({
            "id": comment.id,
            "postId": comment.postId,
            "userId": comment.userId,
            "content": comment.content,
            "updatedAt": comment.updatedAt,
            "username": comment.user.username,
            "email": comment.user.email,
            "avatarUrl": comment.user.avatarUrl,
            "likesCount": likes_count,
            "commentsCount": comments_count
        })
    
    return jsonify(comment_list), 200

@app.route('/getPostCommentsById', methods=['GET'])
@token_required
def getPostCommentssById(current_user):
    post_id = request.args.get('postId')
    parent_comment_id = request.args.get('parentCommentId') 
    comments = Comment.query.filter_by(postId=post_id, parentCommentId=parent_comment_id).all()
    comment_list = []

    for comment in comments:
        likes_count = CommentLikes.query.filter_by(commentId=comment.id).count()
        comments_count = Comment.query.filter_by(parentCommentId=comment.id).count()

        comment_list.append({ 
            "id": comment.id,
            "postId": comment.postId,
            "userId": comment.userId,
            "content": comment.content,
            "updatedAt": comment.updatedAt,
            "username": comment.user.username,
            "email": comment.user.email,
            "avatarUrl": comment.user.avatarUrl,
            "likesCount": likes_count,
            "commentsCount": comments_count,
            "parentCommentId": comment.parentCommentId
        })
    
    return jsonify(comment_list), 200

@app.route('/createPostComment', methods=['POST'])
@token_required
def createComment(current_user):
    data = request.get_json()
    new_comment = Comment(userId=current_user.id, postId=data['id'], content=data['content'], parentCommentId=data.get('parentCommentId'))

    db.session.add(new_comment)
    db.session.commit()

    return jsonify({
        "id": new_comment.id,
        "postId": new_comment.postId,
        "userId": new_comment.userId,
        "content": new_comment.content,
        "updatedAt": new_comment.updatedAt,
        "username": current_user.username,
        "email": current_user.email,
        "avatarUrl": current_user.avatarUrl,
        "likesCount": 0,
        "sharesCount": 0,
        "commentsCount": 0,
        "parentCommentId": new_comment.parentCommentId
    }), 201

# Initialize DB
with app.app_context():
    db.create_all()

# Run the server
if __name__ == '__main__':
    app.run()
