FROM ubuntu:18.04
COPY . /app
WORKDIR /app
RUN apt-get update && apt-get install -y python-pip libssl-dev libpq-dev build-essential libfontconfig1 libfontconfig1-dev
RUN pip install setuptools pip --upgrade --force-reinstall
RUN pip install -r requirements.txt
EXPOSE 5000
ENV APP_SETTINGS project.config.DevelopmentConfig
CMD python ./manage.py create_db
CMD python ./manage.py db migrate
CMD python ./manage.py db init
CMD python ./manage.py create_admin
CMD python ./manage.py runserver --host 0.0.0.0
