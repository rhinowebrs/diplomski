import os

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or '2525'
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or 'postgresql://postgres:2525@localhost/diplomski'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
