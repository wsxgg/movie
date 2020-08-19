from app import db
from datetime import datetime
from werkzeug.security import check_password_hash

# 用户模型
class User(db.Model):
    __tablename__ = 'user'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True)
    pwd = db.Column(db.String(100))
    email = db.Column(db.String(100), unique=True)
    phone = db.Column(db.String(11), unique=True)
    info = db.Column(db.Text)
    face = db.Column(db.String(255))
    add_time = db.Column(db.DateTime, index=True, default=datetime.now)
    uuid = db.Column(db.String(255), unique=True)   
    userlogs = db.relationship("Userlog", backref='user')       # 登陆日志
    comments = db.relationship("Comment", backref='user')       # 评论
    moviecols = db.relationship("Moviecol", backref='user')     # 收藏


    def __repr__(self):
        return "<user %s>" % self.name

    def check_pwd(self, pwd):
        return check_password_hash(self.pwd, pwd)
        

# 用户登录日志
class Userlog(db.Model):
    __table__name = 'user_log'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    ip = db.Column(db.String(100))
    add_time = db.Column(db.DateTime, index=True, default=datetime.now)

    def __repr__(self):
        return "<Userlog %d>" % self.id

# 标签
class Tag(db.Model):
    __tablename__ = 'tag'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(32), unique=True)
    add_time = db.Column(db.DateTime, index=True, default=datetime.now)
    movies = db.relationship("Movie", backref='tag')

    def __repr__(self):
        return "<Tag %s>" % self.name

# 电影
class Movie(db.Model):
    __tablename__ = 'movie'

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(255), unique=True)
    url = db.Column(db.String(255), unique=True)
    info = db.Column(db.Text)
    logo = db.Column(db.String(255), unique=True)
    star = db.Column(db.SmallInteger)       # 星级
    playnum = db.Column(db.BigInteger)      # 播放数目
    commentnum = db.Column(db.BigInteger)       # 评论数目
    tag_id = db.Column(db.Integer, db.ForeignKey("tag.id"))
    area = db.Column(db.String(255))        # 产地
    release_time = db.Column(db.Date)       # 上映时间
    length = db.Column(db.String(100))      # 时长
    add_time = db.Column(db.DateTime, index=True, default=datetime.now)  # 添加时间
    comments = db.relationship("Comment", backref='movie')  # 评论
    moviecols = db.relationship("Moviecol", backref='movie')    # 收藏

    def __repr__(self):
        return "<Movie %s>" % self.title

# 预告
class Preview(db.Model):
    __tablename__ = 'preview'

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(255), unique=True)
    logo = db.Column(db.String(255), unique=True)
    add_time = db.Column(db.DateTime, index=True, default=datetime.now)

    def __repr__(self):
        return "<Preview %s>" % self.title


# 评论
class Comment(db.Model):
    __tablename__ = 'comment'

    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text)
    movie_id = db.Column(db.Integer, db.ForeignKey("movie.id"))
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    add_time = db.Column(db.DateTime, index=True, default=datetime.now)

    def __repr__(self):
        return "<Comment %d>" % self.id


# 电影收藏
class Moviecol(db.Model):
    __tablename__ = 'moviecol'

    id = db.Column(db.Integer, primary_key=True)
    movie_id = db.Column(db.Integer, db.ForeignKey("movie.id"))
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    add_time = db.Column(db.DateTime, index=True, default=datetime.now)

    def __repr__(self):
        return "<Moviecol %d>" % self.id

# 权限   对各个模块增删改的权限
class Auth(db.Model):
    __tablename__ = 'auth'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), unique=True)
    url = db.Column(db.String(255))
    add_time = db.Column(db.DateTime, index=True, default=datetime.now)

    def __repr__(self):
        return "<Auth %s>" % self.name

# 角色 可以将管理员划分未电影管理员，日志管理员等
class Role(db.Model):
    __tablename__ = 'role'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True)
    auths = db.Column(db.String(600))
    add_time = db.Column(db.DateTime, index=True, default=datetime.now)
    admin = db.relationship("Admin", backref='role')        


    def __repr__(self):
        return "<Role %s>" % self.name


# 管理员
class Admin(db.Model):
    __tablename__ = "admin"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True) 
    pwd = db.Column(db.String(100))
    is_super = db.Column(db.Boolean)
    role_id = db.Column(db.Integer, db.ForeignKey("role.id"))       # 所属角色
    add_time = db.Column(db.DateTime, index=True, default=datetime.now)
    adminlogs = db.relationship("Adminlog", backref='admin')        # 管理员登陆日志
    oplog = db.relationship("Oplog", backref='admin')       # 管理员操作日志

    def __repr__(self):
        return "<admin %s>" % self.name

    # 检查密码的方法
    def check_pwd(self, pwd):
        return check_password_hash(self.pwd, pwd)

# 管理员登陆日志
class Adminlog(db.Model):
    __table__name = 'adminlog'

    id = db.Column(db.Integer, primary_key=True)
    admin_id = db.Column(db.Integer, db.ForeignKey('admin.id'))
    ip = db.Column(db.String(100))
    add_time = db.Column(db.DateTime, index=True, default=datetime.now)

    def __repr__(self):
        return "<Adminlog %d>" % self.id

# 操作日志
class Oplog(db.Model):
    __table__name = 'oplog'

    id = db.Column(db.Integer, primary_key=True)
    admin_id = db.Column(db.Integer, db.ForeignKey('admin.id'))
    ip = db.Column(db.String(100))
    add_time = db.Column(db.DateTime, index=True, default=datetime.now)
    reason = db.Column(db.String(600))

    def __repr__(self):
        return "<oplog %d>" % self.id
