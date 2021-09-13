from flask import Flask, request
from flask_restful import Resource, Api
from flask_jwt import JWT, jwt_required, current_identity
# from flask_migrate import Migrate
import os
from flask_bcrypt import Bcrypt
import ast
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timedelta

bcrypt = Bcrypt()

#################################   App Configuration  #################################
app = Flask(__name__)
app.config['SECRET_KEY'] = 'would_be_an_environment_variable_in_a_real_project'
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_EXPIRATION_DELTA'] = timedelta(minutes=30)
db = SQLAlchemy(app)
# Migrate(app, db)


#################################   Security Checks  #################################

def authenticate(username, password):
    user = User.query.filter_by(username=username).first()
    # if user and password == user.password:  # need to hash
    if user and bcrypt.check_password_hash(user.password, password):
        return user


def identity(payload):
    user_id = payload['identity']
    return User.query.get(user_id)


#################################   App Configuration  #################################

api = Api(app)
jwt = JWT(app, authenticate, identity)
db = SQLAlchemy(app)





#################################   Models  #################################

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)

    def __repr__(self):
        return self.username


class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    message = db.Column(db.Text, nullable=False)
    subject = db.Column(db.String(30), nullable=False)
    creation_date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    was_read = db.Column(db.Boolean, default=False)

    def __repr__(self):
        return f"subject: {self.subject}\nsender_id: {self.sender_id}\nreceiver_id: {self.receiver_id}\nwas_read: {self.was_read}"

    def json(self):
        return {
                'id': self.id,
                'sender': User.query.get(self.sender_id).username,
                'receiver': User.query.get(self.receiver_id).username,
                'subject:': self.subject,
                'message': self.message,
                'creation_date': self.creation_date.strftime("%d/%m/%Y, %H:%M"),
                'was_read': str(self.was_read)
                }




#################################   Messages routes  #################################

class Write_message(Resource):

    @jwt_required()
    def post(self):

        data_dict = ast.literal_eval(request.data.decode('utf-8'))
        receiver_username = data_dict.get('receiver_username')
        subject = data_dict.get('subject')
        message = data_dict.get('message')
        if not(receiver_username and subject and message):
            return "Please provide values for the following keys: 'receiver_username', 'subject', 'message'"
        user_id = current_identity.id
        receiver_user = User.query.filter_by(username=receiver_username).first()
        if receiver_user:
            msg = Message(sender_id=user_id, receiver_id=receiver_user.id, subject=subject, message=message)
            db.session.add(msg)
            db.session.commit()
            return "Message Sent!"
        return "The user you want to send a messages to does not exist, make sure you have the right username."

class Get_all_messages_sent_to_me(Resource):

    @jwt_required()
    def get(self):
        user_id = current_identity.id
        messages = Message.query.order_by(Message.creation_date.desc()).filter_by(receiver_id=user_id).all()
        return {'messages': [msg.json() for msg in messages]}



class Get_all_unread_messages_sent_to_me(Resource):

    @jwt_required()
    def get(self):
        user_id = current_identity.id
        messages = Message.query.order_by(Message.creation_date.desc()).filter_by(receiver_id=user_id, was_read=False).all()
        return {'messages': [msg.json() for msg in messages]}

class Get_all_messages_sent_by_me(Resource):

    @jwt_required()
    def get(self):
        user_id = current_identity.id
        messages = Message.query.order_by(Message.creation_date.desc()).filter_by(sender_id=user_id).all()
        return {'messages': [msg.json() for msg in messages]}

class Single_Message(Resource):

    @jwt_required()
    def get(self, message_id):
        if message_id is None:
            return "Please provide a message id"
        user_id = current_identity.id
        msg = Message.query.filter_by(receiver_id=user_id, id=message_id).first()
        if msg:
            msg.was_read = True
            db.session.commit()
            return msg.json()
        return "Did not find a message of that id sent to you."

    @jwt_required()
    def delete(self, message_id):
        if message_id is None:
            return "Please provide a message id"
        user_id = current_identity.id
        msg_query = Message.query.filter_by(id=message_id)
        msg = msg_query.first()
        if msg and (user_id == msg.receiver_id or user_id == msg.sender_id):
            msg_query.delete()
            db.session.commit()
            return f"deleted message {message_id}"
        return "Did not find a message of that id sent to/by you."

api.add_resource(Get_all_messages_sent_to_me, '/get_all_messages_sent_to_me/')
api.add_resource(Get_all_unread_messages_sent_to_me, '/get_all_unread_messages_sent_to_me/')
api.add_resource(Get_all_messages_sent_by_me, '/get_all_messages_sent_by_me/')
api.add_resource(Single_Message, '/message/<int:message_id>')
api.add_resource(Write_message, '/write_message')



#################################   Users Routes  #################################

class Register(Resource):
    def post(self):
        data_dict = ast.literal_eval(request.data.decode('utf-8'))
        username = data_dict.get('username')
        password = data_dict.get('password')
        if User.query.filter_by(username=username).first():
            return "This username is taken, try another."
        # if username is None or len(username) == 0 or password is None or len(password) == 0:
        if username and password:
            hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
            user = User(username=username, password=hashed_password)
            db.session.add(user)
            db.session.commit()
            return "User created!"
        return "Please provide a username and a password."



api.add_resource(Register, '/register')



if __name__ == '__main__':
    app.run(debug=True)  # set it to False before deploying

