import os
from dotenv import load_dotenv

load_dotenv()  # take environment variables from .env.

# You need to replace the next values with the appropriate values for your configuration
basedir = os.path.abspath(os.path.dirname(__file__))
DEBUG = False
PORT = 80
HOST = "skaterska.pythonanywhere.com"
SQLALCHEMY_ECHO = False
SQLALCHEMY_TRACK_MODIFICATIONS = True
SQLALCHEMY_DATABASE_URI = "mysql+pymysql://{DB_USER}:{DB_PASS}@{DB_ADDR}/{DB_NAME}".format(
    DB_USER="skaterska",
    DB_PASS="bismillah",
    DB_ADDR="skaterska.mysql.pythonanywhere-services.com",
    DB_NAME="skaterska$messages02"
)
SQLALCHEMY_MIGRATE_REPO = os.path.join(basedir, 'db_repository')
PAGINATION_PAGE_SIZE = 5
PAGINATION_PAGE_ARGUMENT_NAME = 'page'
SECRET_KEY = 'SECRET_AJA'
SECURITY_PASSWORD_SALT = 'my_precious_two'

# mail settings
MAIL_SERVER = 'smtp.googlemail.com'
MAIL_PORT = 465
MAIL_USE_TLS = False
MAIL_USE_SSL = True

# gmail authentication
MAIL_USERNAME = os.environ['APP_MAIL_USERNAME']
MAIL_PASSWORD = os.environ['APP_MAIL_PASSWORD']

# mail accounts
MAIL_DEFAULT_SENDER = 'from@example.com'

UPLOADED_IMAGES_DEST = os.path.join("static", "images")  # manage root folder
