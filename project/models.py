"""Model Objects."""
import datetime

import jwt

from project import db, bcrypt, app
from sqlalchemy.orm import relationship


class User(db.Model):
    """User object."""

    __tablename__ = "user"

    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String, unique=True, nullable=False)
    password = db.Column(db.String, nullable=False)
    registered_on = db.Column(db.DateTime, nullable=False)
    admin = db.Column(db.Boolean, nullable=False, default=False)
    quota = db.Column(db.Integer)
    resources = relationship("Resource", backref="owner", cascade="all, delete-orphan")

    def __init__(self, email, password, quota=None, admin=False):
        """Initializer for User object."""
        self.email = email
        self.password = bcrypt.generate_password_hash(password)
        self.admin = admin
        self.quota = quota
        self.registered_on = datetime.datetime.now()

    def is_authenticated(self):
        """Return True if the user is authenticated."""
        return True

    def is_active(self):
        """True, as all users are active."""
        return True

    def is_anonymous(self):
        """False, as anonymous users aren't supported."""
        return False

    def get_id(self):
        """Return the email address to satisfy Flask-Login's requirements."""
        return unicode(self.id)

    @property
    def is_admin(self):
        """Method to check if user is admin."""
        return (self.admin == True)

    def save(self):
        """Overriding save method to set created on."""
        if not self.id:
            db.session.add(self)
        return db.session.commit()

    def check_password(self, password):
        """Method to check password."""
        return bcrypt.check_password_hash(self.password, password)

    def encode_auth_token(self):
        """
        Generate the Auth Token.

        :return: string
        """
        try:
            payload = {
                'exp': datetime.datetime.utcnow() + datetime.timedelta(seconds=20, hours=1),
                'iat': datetime.datetime.utcnow(),
                'sub': self.id
            }
            return jwt.encode(
                payload,
                app.config.get('SECRET_KEY'),
                algorithm='HS256'
            )
        except Exception as e:
            return e

    @staticmethod
    def decode_auth_token(auth_token):
        """Decode the auth token."""
        try:
            payload = jwt.decode(auth_token, app.config.get('SECRET_KEY'))
            return {"result": payload['sub'], "message": "Success"}
        except jwt.ExpiredSignatureError:
            return {"result": False, "message": 'Signature expired. Please log in again.'}
        except jwt.InvalidTokenError:
            return {"result": False, "message": 'Invalid token. Please log in again.'}

    def delete(self):
        """Delete entry."""
        db.session.delete(self)
        return db.session.commit()

    def __repr__(self):
        """Representation of User object."""
        return 'User - email: {}'.format(self.email)


class Resource(db.Model):
    """Resources object."""

    __tablename__ = "resource"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String, nullable=False)
    created_on = db.Column(db.DateTime, nullable=False)
    owner_id = db.Column(db.Integer, db.ForeignKey('user.id'))

    def __init__(self, name, owner_id):
        """Initializer."""
        self.name = name
        self.owner_id = owner_id
        self.created_on = datetime.datetime.now()

    def save(self):
        """Overriding save method to set created on."""
        if not self.id:
            db.session.add(self)
        return db.session.commit()

    def __repr__(self):
        """Representation of Resource object."""
        return 'Resource:[{id}] name {name}'.format(id=self.id,
                                                    name=self.name)
