from flask import Flask, render_template
from flask_sqlalchemy import SQLAlchemy
from flask_redis import FlaskRedis
import os
import pymysql

pymysql.install_as_MySQLdb()

app = Flask(__name__)
app.debug = True

# 链接数据库
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://root:Wushuqian789.@127.0.0.1:3306/movie' 
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True     # 追踪修改
# Redis数据库
app.config['REDIS_URL'] = 'redis://127.0.0.1:6379/0'
# 定义文件上传路径
app.config['UP_DIR'] = os.path.join(os.path.abspath(os.path.dirname(__file__)), "static/uploads/")
app.config['MOVIES_DIR'] = os.path.join(os.path.abspath(os.path.dirname(__file__)), "static/uploads/movies/")
app.config['PREVIEWS_DIR'] = os.path.join(os.path.abspath(os.path.dirname(__file__)), "static/uploads/previews/")
app.config['US_DIR'] = os.path.join(os.path.abspath(os.path.dirname(__file__)), "static/uploads/users/")
# 生成db对象
db = SQLAlchemy(app)
# 生成redis对象
rd = FlaskRedis(app)

# secret_key
app.config['SECRET_KEY'] = "aslasfobjbfjk12bbkf3"

# 注册蓝图， 把蓝图导入放到这里可以避免循环导入
from app.home import home as home_blueprint
from app.admin import admin as admin_blueprint

# 注册蓝图
app.register_blueprint(home_blueprint)
app.register_blueprint(admin_blueprint, url_prefix="/admin")


# 错误页面
@app.errorhandler(404)
def page_not_found(error):
    return render_template('home/404.html'), 404






