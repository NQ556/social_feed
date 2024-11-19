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

        except jwt.ExpiredSignatureError:
            return jsonify({"message": "Token has expired!"}), 401
        
        except jwt.InvalidTokenError:
            return jsonify({"message": "Token is invalid!"}), 403
        
        return f(current_user, *args, **kwargs)
    
    return decorated

@app.route('/refreshToken', methods=['POST'])
def refresh_token():
    data = request.get_json()
    refresh_token = data.get('refresh_token')
    
    if not refresh_token:
        return jsonify({"message": "Refresh token is missing!"}), 403

    try:
        data = jwt.decode(refresh_token, app.config['SECRET_KEY'], algorithms=["HS256"])
        current_user = User.query.get(data['user_id'])

        #if not current_user:
        #    return jsonify({"message": "User not found!"}), 404
        
        # Generate a new access token
        new_access_token = jwt.encode({
            "user_id": current_user.id,
            "exp": datetime.utcnow() + timedelta(hours=1)
        }, app.config['SECRET_KEY'], algorithm="HS256")

        # Generate a new refresh token
        new_refresh_token = jwt.encode({
            "user_id": current_user.id,
            "exp": datetime.utcnow() + timedelta(days=7)
        }, app.config['SECRET_KEY'], algorithm="HS256")
        
        return jsonify({
            "message": "Token refreshed successfully",
            "access_token": new_access_token,
            "refresh_token": new_refresh_token
        }), 200
    
    except jwt.ExpiredSignatureError:
        return jsonify({"message": "Refresh token expired!"}), 401
    except jwt.InvalidTokenError:
        return jsonify({"message": "Invalid refresh token!"}), 403


# Routes
@app.route('/signUp', methods=['POST'])
def signUp():
    data = request.get_json()
    hashed_password = bcrypt.generate_password_hash(data['password']).decode('utf-8')
    
    new_user = User(email=data['email'], username=data['username'], password=hashed_password, avatarUrl=data['avatarUrl'])
    db.session.add(new_user)
    db.session.commit()

    # Generate access token
    access_token = jwt.encode({
        "user_id": new_user.id,
        "exp": datetime.utcnow() + timedelta(hours=1)
    }, app.config['SECRET_KEY'], algorithm="HS256")

    # Generate refresh token
    refresh_token = jwt.encode({
        "user_id": new_user.id,
        "exp": datetime.utcnow() + timedelta(days=7)
    }, app.config['SECRET_KEY'], algorithm="HS256")
    
    return jsonify({
        "message": "User registered successfully!",
        "userId": new_user.id,
        "accessToken": access_token,
        "refreshToken": refresh_token
    }), 201


@app.route('/signIn', methods=['POST'])
def signIn():
    data = request.get_json()
    user = User.query.filter_by(email=data['email']).first()
    
    if user and bcrypt.check_password_hash(user.password, data['password']):
        # Generate access token
        access_token = jwt.encode({
            "user_id": user.id,
            "exp": datetime.utcnow() + timedelta(hours=1)
        }, app.config['SECRET_KEY'], algorithm="HS256")

        # Generate refresh token
        refresh_token = jwt.encode({
            "user_id": user.id,
            "exp": datetime.utcnow() + timedelta(days=7)
        }, app.config['SECRET_KEY'], algorithm="HS256")
        
        return jsonify({
            "message": "Login successful!", 
            "userId": user.id, 
            "accessToken": access_token,
            "refreshToken": refresh_token}), 200
    
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

@app.route('/getPostsById', methods=['GET'])
@token_required
def getPostsById(current_user):
    posts = Comment.query.filter_by(userId=current_user.id).all()
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

@app.route('/createPostLike', methods=['POST'])
@token_required
def createPostLike(current_user):
    data = request.get_json()
    post_id = data.get('postId')

    post = Post.query.get(post_id)
    if not post:
        return jsonify({"message": "Post not found"}), 404

    # Check if the user has already liked the post
    existing_like = PostLikes.query.filter_by(postId=post_id, userId=current_user.id).first()
    if existing_like:
        return jsonify({"message": "User has already liked this post"}), 400

    # Create a new like
    new_like = PostLikes(postId=post_id, userId=current_user.id)
    db.session.add(new_like)
    db.session.commit()

    likes_count = PostLikes.query.filter_by(postId=post_id).count()

    return jsonify({
        "message": "Post liked successfully",
        "postId": post_id,
        "likesCount": likes_count
    }), 201

@app.route('/getLikedPostsByUserId', methods=['GET'])
@token_required
def getLikedPostsByUserId(current_user):
    liked_posts = PostLikes.query.filter_by(userId=current_user.id).all()
    
    post_list = []

    for like in liked_posts:
        post = Post.query.get(like.postId)

        if post:
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

# Initialize DB
with app.app_context():
    db.create_all()

# Run the server
if __name__ == '__main__':
    app.run()
