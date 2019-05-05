# To run locally
 --> pip install -r requirements.txt

# Docker setup

## To build
 --> docker build --tag chainstack_app .

## To run
 --> docker run --name python-app -p 5000:5000 chainstack_app

## To stop and remove container
 --> docker rm $(docker stop $(docker ps -a -q  --filter ancestor=chainstack_app))


#TODO
-- Add test suite.
-- Add token to be refreshed with login.
-- Invalidate old token for the same user.