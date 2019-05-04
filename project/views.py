"""View Functions."""
from flask import request, jsonify
from flask_restful import Resource as BaseResource
from flask_login import (login_user, current_user,
                         login_required, logout_user)

from project import app, bcrypt, login_manager
from project.models import User, Resource
EXCLUDE_AUTH_VIEWS = ['login', 'logout']


@login_manager.user_loader
def user_loader(user_id):
    """Given *user_id*, return the associated User object or None."""
    user = User.query.get(user_id)
    if user:
        return user


@app.before_request
def require_authorization():
    """BEFORE REQUEST HANDLER. Require Authorization."""
    if any([x for x in EXCLUDE_AUTH_VIEWS if x in request.path]):
        return None
    # print view_func.exclude_from_authorization
    if current_user.is_authenticated:
        get_token_decode_data = current_user.decode_auth_token(request.headers.get("Authorization"))
        if not get_token_decode_data.get("result"):
            return jsonify({'message': get_token_decode_data.get("message")})


@login_manager.unauthorized_handler
def unauthorized():
    """Unauthorized activity handler."""
    return {"message": "Unauthorized activity. Please contact admin."}


def admin_view(func):
    """Decorator to check if current_user is admin."""
    def wrapper(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            return {'message': 'You are not privilaged to perform this action.'}
        return func(*args, **kwargs)
    return wrapper


class UserViews(BaseResource):
    """User related views."""

    decorators = [login_required]

    def get(self, user_id):
        """GET method handler."""
        user = User.query.get(user_id)
        if user:
            return {'user_id': user.id,
                    'email': user.email,
                    'is_admin': user.is_admin,
                    'message': 'success',
                    'quota': user.quota or 'Not set'
                    }
        return {'message': 'Cannot find User.'}, 401

    @admin_view
    def post(self):
        """POST method handler."""
        # import ipdb; ipdb.set_trace()
        email = request.form.get('email')
        password = request.form.get('password')
        quota = request.form.get('quota', None)
        is_admin = request.form.get('is_admin', False)
        if not email or not password:
            return {'message': 'Cannot save user without email and password.'}

        user = User(email=email,
                    password=password,
                    quota=quota,
                    admin=is_admin)
        try:
            user.save()
        except Exception as e:
            return {'message': 'User save failed with message {msg}'.format(
                msg=e),
                'email': user.email,
            }
        else:
            return {'message': 'User saved',
                    'email': user.email,
                    'id': user.id
                    }

    def put(self, user_id):
        """PUT method handler."""
        user = User.query.get(user_id)
        if not user:
            return {'message': 'Cannot find User.'}
        # admin has access to all
        if current_user != user:
            if not current_user.is_admin:
                return {'message': 'You are not privilaged to perform this action.'}
        password = request.form.get('password')
        previous_password = request.form.get('previous_password')
        quota = request.form.get('quota', None)
        if current_user.is_admin:
            if not password:
                password = user.password
            if not quota:
                quota = user.quota
        else:
            if quota:
                return {'message': 'You are not privilaged to update quota. Contact admin.'}
            else:
                # but quota needs to be set if not present :)
                quota = user.quota
            if not password or not previous_password:
                return {'message': 'Password data incomplete.'}
            if not bcrypt.check_password_hash(user.password, previous_password):
                return {'message': 'Previous password is wrong.'}
        user.password = bcrypt.generate_password_hash(password)
        is_admin = request.form.get('is_admin', user.admin)
        user.admin = is_admin
        user.quota = quota
        try:
            user.save()
        except Exception as e:
            return {'message': 'User save failed with message {msg}'.format(
                msg=e),
                'email': user.email,
            }
        else:
            return {'message': 'User details updated.',
                    'id': user.id,
                    'email': user.email,
                    'quota': user.quota,
                    }

    @admin_view
    def delete(self, user_id):
        """DELETE method handler."""
        user = User.query.get(user_id)
        try:
            user.delete()
        except Exception as e:
            return {'message': 'User delete failed with message {msg}'.format(
                msg=e)
            }
        else:
            return {'message': 'User deleted',
                    'id': user.id,
                    'email': user.email,
                    'quota': user.quota,
                    }


class ResourceViews(BaseResource):
    decorators = [login_required]

    def post(self, user_id, resource_id=None):
        # create resource for that user
        # if quota is null -- create
        # if quota is set, check number of resources remaining
        resource_name = request.form.get('name')
        owner_id = request.form.get('owner_id', user_id)
        # check if user has quota
        user = User.query.get(owner_id)
        if not user:
            return {'message': 'Cannot find user.'}
        if user.quota and len(user.resources) >= user.quota:
            return {'message': 'User with ID: {id} cannot have more resource since quota is over.'.format(id=owner_id)}

        if not resource_name:
            return {'message': 'Cannot create resource without name.'}
        resource = Resource(name=resource_name, owner_id=owner_id)
        resource.save()
        return {'message': 'Resource saved',
                'name': resource.name,
                'owner_id': resource.owner_id,
                'id': resource.id
                }

    def get(self, user_id, resource_id=None):
        user = User.query.get(user_id)
        if not user:
            return {'message': 'User not found'}

        if resource_id:
            resource = Resource.query.get(resource_id)
            if resource:
                if user.is_admin or resource.owner.id == user_id:
                    return {'message': "Success",
                            'name': resource.name,
                            'owner_id': resource.owner_id,
                            'id': resource.id
                            }
        return {'message': 'Resource not found. Please check the ID.'}


class ListResourceViews(BaseResource):
    decorators = [login_required]

    def get(self, user_id):
        user = User.query.get(user_id)
        if not user:
            return {'message': 'User not found'}

        owner_id = request.args.get('owner', 0)
        owner = User.query.get(owner_id)
        data = []
        if user.is_admin:
            if owner:
                resources = Resource.query.filter(
                    Resource.owner_id == owner_id).all()
            else:
                resources = Resource.query.all()
        else:
            resources = Resource.query.filter(
                Resource.owner_id == user_id).all()
        if resources:
            for each_res in resources:
                data.append({'resource_name': each_res.name,
                             'resource_id': each_res.id,
                             'associated_user_id': each_res.owner.id,
                             'associated_user_email': each_res.owner.email,
                             })
            return {
                'message': 'Resources found',
                'user_id': user_id,
                'resources': data
            }

        return {
            'message': 'No resources found',
            'user_id': user_id,
            'resources': data
        }


class AdminViews(BaseResource):
    """Admin views."""

    decorators = [login_required, admin_view]

    def get(self, user_id):
        """Admin GET of all user details."""
        user = User.query.get(user_id)
        data = []
        if user and user.is_admin:
            all_users = User.query.all()
            if all_users:
                for each_user in all_users:
                    data.append({'user_id': each_user.id,
                                 'user_email': each_user.email,
                                 'is_admin': each_user.is_admin,
                                 'quota': each_user.quota,
                                 'resources': [{'resource_name': x.name,
                                                'resource_id': x.id}
                                               for x in each_user.resources],
                                 })
            return {'user_id': user.id,
                    'email': user.email,
                    'message': 'success',
                    'users_data': data
                    }
        return {'message': 'You don\'t have privilage to view this.'}


class LoginViews(BaseResource):
    """Login views."""

    def post(self):
        """Login the user and return auth key."""
        try:
            # fetch the user data
            user = User.query.filter_by(
                email=request.form.get('email'),
            ).first()
            if user and user.check_password(request.form.get('password')):
                login_user(user, remember=True)
                auth_token = user.encode_auth_token()
                if auth_token:
                    response = {
                        'status': 'success',
                        'id': user.id,
                        'email': user.email,
                        'quota': user.quota,
                        'message': 'Successfully logged in.',
                        'auth_token': auth_token.decode()
                    }
                    return response, 200
            else:
                return {'message': 'User not found for the provided credentials.'}, 200
        except Exception, e:
            response = {
                'message': 'Error occured. {message}. Try again'.format(message=e)
            }
            return response, 500


class LogoutViews(BaseResource):
    """Logout views."""

    def post(self):
        """Logout user."""
        if not current_user.is_authenticated:
            return {
                "message": "No user logged-in.",
            }
        logout_user()
        return {
            "message": "User logged out successfully.",
        }
