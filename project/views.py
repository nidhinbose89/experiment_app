from flask import request
from flask_restful import Resource as BaseResource

from project import bcrypt
from project.models import User, Resource


class UserViews(BaseResource):

    def get(self, user_id):
        user = User.query.get(user_id)
        if user:
            return {'user_id': user.id,
                    'email': user.email,
                    'message': 'success',
                    'quota': user.quota or 'Not set'
                    }
        return {'message': 'Cannot find User.'}

    def post(self):
        # create user if the current user is admin
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
        user = User.query.get(user_id)
        if not user:
            return {'message': 'Cannot find User.'}
        password = request.form.get('password', user.email)
        previous_password = request.form.get('previous_password')
        if password and previous_password:
            if not bcrypt.check_password_hash(user.password, previous_password):
                return {'message': 'Previous password is wrong.'}
            user.password = bcrypt.generate_password_hash(password)
        quota = request.form.get('quota', user.quota)
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

    def delete(self, user_id):
        # if current user is admin
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
    def get(self, user_id):
        user = User.query.get(user_id)
        data = []
        if user and user.is_admin:
            all_users = User.query.all()
            if all_users:
                for each_user in all_users:
                    data.append({'user_id': each_user.id,
                                 'user_email': each_user.email,
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
