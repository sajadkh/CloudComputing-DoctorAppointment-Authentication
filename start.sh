#!/bin/bash

echo "start authentication service...."
echo "django makemigrations..."
python manage.py makemigrations authCore
echo "django migrate..."
python manage.py migrate
echo "run server..."
python manage.py runserver 0.0.0.0:8000
