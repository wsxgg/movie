from flask import Blueprint

# 定义蓝图
admin = Blueprint("admin", __name__)  

from app.admin import views
