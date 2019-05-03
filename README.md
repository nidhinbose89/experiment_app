# To install all the requirements
pip install -r requirements.txt

# To set the configuration
export APP_SETTINGS='project.config.DevelopmentConfig'

# To init DB
./manage.py db init

# To create DB
./manage.py create_db

# To migrate DB
 ./manage.py db migrate

# To create admin
./manage.py create_admin


#TODO
-- Docker setup.
-- Add test suite.
-- Add token to be refreshed with login.