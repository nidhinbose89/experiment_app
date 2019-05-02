import datetime

from project import db, bcrypt
from sqlalchemy.orm import relationship


class User(db.Model):

    __tablename__ = "user"

    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String, unique=True, nullable=False)
    password = db.Column(db.String, nullable=False)
    registered_on = db.Column(db.DateTime, nullable=False)
    admin = db.Column(db.Boolean, nullable=False, default=False)
    quota = db.Column(db.Integer)
    resources = relationship("Resource", backref="owner", cascade="all, delete-orphan")

    def __init__(self, email, password, quota=None, admin=False):
        self.email = email
        self.password = bcrypt.generate_password_hash(password)
        self.admin = admin
        self.quota = quota
        self.registered_on = datetime.datetime.now()

    @property
    def is_admin(self):
        return (self.admin == True)

    def save(self):
        """Overriding save method to set created on."""
        if not self.id:
            db.session.add(self)
        return db.session.commit()

    def delete(self):
        """Delete entry."""
        db.session.delete(self)
        return db.session.commit()

    def __repr__(self):
        return 'User - email: {}'.format(self.email)


class Resource(db.Model):

    __tablename__ = "resource"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String, nullable=False)
    created_on = db.Column(db.DateTime, nullable=False)
    owner_id = db.Column(db.Integer, db.ForeignKey('user.id'))

    def __init__(self, name, owner_id):
        self.name = name
        self.owner_id = owner_id
        self.created_on = datetime.datetime.now()

    def save(self):
        """Overriding save method to set created on."""
        if not self.id:
            db.session.add(self)
        return db.session.commit()

    def __repr__(self):
        return 'Resource:[{id}] name {name}'.format(id=self.id,
                                                    name=self.name)
