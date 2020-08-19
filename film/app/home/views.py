from . import home
from flask import render_template, redirect, url_for, flash, session, request, jsonify, Response
from app.home.forms import RegistForm, LoginForm, UserDetailForm, PwdForm, CommentForm
from werkzeug.security import generate_password_hash
import uuid
from app import db, app, rd
from app.models import User, Userlog, Preview, Tag, Movie, Comment, Moviecol
import functools
import os
from datetime import datetime



# 定义登陆装饰器
def user_login_require(view_func):
    @functools.wraps(view_func)
    def wrapper(*args, **kwargs):
        if session.get('user') is not None:
            return view_func(*args, **kwargs)
        else:
            return redirect(url_for("home.login"))
    return wrapper

# 定义修改文件名称的方法
def change_filename(filename):
    file_info = os.path.splitext(filename)
    # print(file_info[-1])
    filename = datetime.now().strftime("%Y%m%d") + str(uuid.uuid4().hex) + file_info[-1]
    return filename



# 登录页
@home.route("/login", methods=['GET', 'POST'])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        data = form.data
        user = User.query.filter_by(name=data['name']).first()
        if user is None:
            flash("用户名不存在", 'err')
            return redirect(url_for('home.login'))
        elif not user.check_pwd(data['pwd']):
            flash("密码错误", 'err')
            return redirect(url_for('home.login'))
        else:
            session['user'] = user.name
            session['user_id'] = user.id

            # 添加登陆日志
            userlog = Userlog(
                user_id=user.id,
                ip=request.remote_addr
            )
            db.session.add(userlog)
            db.session.commit()
            return redirect(url_for('home.index'))

    return render_template("home/login.html", form=form)


# 登出（返回登陆页面）
@home.route("/logout")
def logout():
    session.pop('user', None)
    session.pop('user_id', None)
    return redirect(url_for("home.index"))


# 注册
@home.route("/register", methods=['GET', 'POST'])
def register():
    form = RegistForm()

    if form.validate_on_submit():
        data = form.data

        user = User(
            name=data['name'],
            email=data['email'],
            phone=data['phone'],
            pwd=generate_password_hash(data['pwd']),
            uuid=uuid.uuid4().hex
        )
        db.session.add(user)
        db.session.commit()
        flash('注册成功', 'ok')

    return render_template("home/register.html", form=form)


# 用户中心
@home.route("/user", methods=['GET', 'POST'])
@user_login_require
def user():
    form = UserDetailForm()
    user = User.query.get(session['user_id'])

    # 设置初始值（其余能设置的都在模板设置了）
    form.info.data = user.info

    if form.validate_on_submit():
        data = form.data

        # 保存用户名
        name_count = User.query.filter_by(name=data['name']).count()
        if name_count == 1 and user.name != data['name']:
            flash('用户名已存在', 'err')
            return redirect(url_for('home.user'))
        user.name = data['name']
        # 保存email
        email_count = User.query.filter_by(email=data['email']).count()
        if email_count == 1 and user.email != data['email']:
            flash('该邮箱已被注册', 'err')
            return redirect(url_for('home.user'))
        user.email = data['email']
        # 保存号码
        phone_count = User.query.filter_by(phone=data['phone']).count()
        if phone_count == 1 and user.phone != data['phone']:
            flash('用号码已注册', 'err')
            return redirect(url_for('home.user'))
        user.phone = data['phone']
        # 如果上传了头像，保存用户头像
        print(form.face.data)
        if form.face.data.filename != '':
            file_face = form.face.data.filename     # 获取文件名
            face = change_filename(file_face)        # 格式化文件名
            form.face.data.save(app.config['US_DIR'] + face)     # 保存文件
            user.face = face       # 将文件名保存到数据库
        # 保存简介
        user.info = data['info']
        db.session.add(user)
        db.session.commit()
        flash('修改成功', 'ok')
        return redirect(url_for('home.user'))

    return render_template("home/user.html", form=form, user=user)

# 修改密码
@home.route("/pwd", methods=['GET', 'POST'])
@user_login_require
def pwd():
    form = PwdForm()

    if form.validate_on_submit():
        data = form.data

        user = User.query.get(session['user_id'])
        if not user.check_pwd(data['old_pwd']):
            flash('密码错误', 'err')
            return redirect(url_for('home.pwd'))
        user.pwd = generate_password_hash(data['new_pwd'])
        db.session.add(user)
        db.session.commit()
        flash('修改密码成功, 请重新登陆', 'ok')
        session.pop('user', None)
        session.pop('user_id', None)
        return redirect(url_for('home.login'))

    return render_template("home/pwd.html", form=form)

# 评论记录
@home.route("/comment/<int:page>", methods=['GET'])
@user_login_require
def comment(page=None):
    if page == None:
        page = 1
    page_data = Comment.query.filter_by(user_id=session['user_id']).paginate(page=page, per_page=8, error_out=False)
    return render_template("home/comment.html", page=page, page_data=page_data)

# 登陆日志
@home.route("/loginlog/<int:page>")
@user_login_require
def loginlog(page=None):
    if page == None:
        page = 1

    page_data = Userlog.query.filter_by(user_id=session['user_id']).paginate(page=page, per_page=10, error_out=False)

    return render_template("home/loginlog.html", page=page, page_data=page_data)

# 用户收藏页面列表
@home.route("/moviecol/<int:page>", methods=['GET'])
@user_login_require
def moviecol(page=None):
    if page == None:
        page = 1
    
    page_data = Moviecol.query.order_by(Moviecol.id).paginate(page=page, per_page=10, error_out=False)

    return render_template("home/moviecol.html", page_data=page_data)

# 添加电影收藏
@home.route("/moviecol/add", methods=['GET'])
@user_login_require
def moviecol_add():
    # 获取参数
    mid = request.args.get('mid')
    print(mid)
    uid = request.args.get('uid')
    moviecol_count = Moviecol.query.filter_by(user_id=int(uid),movie_id=int(mid)).count()
    if moviecol_count == 1:
        # 已经收藏
        return jsonify(is_had=1)
    else:
        # 为收藏
        moviecol = Moviecol(
            movie_id=mid,
            user_id=uid
        )
        db.session.add(moviecol)
        db.session.commit()
        
        return jsonify(is_had=0)



# 首页
@home.route("/")
def index():
    # 获取tags等
    tags = Tag.query.all()
    page_data = Movie.query.order_by(Movie.id)

    # 获取查询属性(通过?传参)
    tid = request.args.get('tid', 0)
    if int(tid) != 0:
        page_data = Movie.query.filter_by(tag_id=tid)

    star = request.args.get('star', 0)
    if int(star) != 0:
        page_data = Movie.query.filter_by(star=int(star))

    release = request.args.get('release', 0)     # 上映时间       0: 默认排序  1:从新到旧  2:从旧到新
    if int(release) != 0:
        if int(release) == 1:
            page_data = Movie.query.order_by(Movie.release_time.desc())
        elif int(release) == 0:
            page_data = Movie.query.order_by(Movie.release_time)

    pm = request.args.get('pm', 0)      # 播放量    0：默认排序 1:从高到低, 2:从低到高
    if int(pm) != 0:
        if int(pm) == 1:
            page_data = Movie.query.order_by(Movie.playnum.desc())
        elif int(pm) == 0:
            page_data = Movie.query.order_by(Movie.playnum)

    cm = request.args.get('cm', 0)      # 评论量    0: 默认排序 1:从高到低, 2:从低到高
    if int(cm) != 0:
        if int(cm) == 1:
            page_data = Movie.query.order_by(Movie.commentnum.desc())
        elif int(cm) == 0:
            page_data = Movie.query.order_by(Movie.commentnum)

    page = request.args.get('page', 1)

    # 分页
    page_data = page_data.paginate(page=int(page), per_page=12, error_out=False)

    p = {
        "tid": tid,
        "star": star,
        "release": release,
        "pm": pm,
        "cm": cm,
        'page': page
    }

    return render_template("home/index.html", tags=tags, p=p, page_data=page_data)

# 轮播图
@home.route("/animation")
def animation():
    data = Preview.query.all()
    return render_template("home/animation.html", data=data)

# 搜索
@home.route("/search/<int:page>")
def search(page=None):
    if page == None:
        page = 1
    # 关键字
    key = request.args.get('key', '')
    # 搜索数据库
    page_data = Movie.query.filter(
        Movie.title.ilike("%"+key+"%")
    ).paginate(
        page=page, per_page=12, error_out=False
    )
    count = Movie.query.filter(Movie.title.ilike("%"+key+"%")).count()
    return render_template("home/search.html", page=page, key=key, page_data=page_data, count=count)

# 电影播放页面
@home.route("/play/<int:id>", methods=['GET', 'POST'])
def play(id):
    movie = Movie.query.get_or_404(int(id))
    form = CommentForm()
    page = request.args.get('page', '1')
    comment = Comment.query.filter_by(movie_id=id).paginate(page=int(page), per_page=10, error_out=False)

    # 提交评论表单
    if 'user' in session and form.validate_on_submit():
        data = form.data
        comment = Comment(
            content=data['content'],
            movie_id=id,
            user_id=session['user_id']
        )
        db.session.add(comment)
        flash('评论成功', 'ok')
        movie.commentnum += 1
        db.session.add(movie)
        db.session.commit()

        return redirect(url_for('home.play', id=id))

    movie.playnum += 1
    db.session.add(movie)
    db.session.commit()

    return render_template("home/play.html", movie=movie, form=form, comment=comment)


# 电影播放页面(带弹幕)
@home.route("/video/<int:id>", methods=['GET', 'POST'])
def video(id):
    movie = Movie.query.get_or_404(int(id))
    form = CommentForm()
    page = request.args.get('page', '1')
    comment = Comment.query.filter_by(movie_id=id).paginate(page=int(page), per_page=10, error_out=False)

    # 提交评论表单
    if 'user' in session and form.validate_on_submit():
        data = form.data
        comment = Comment(
            content=data['content'],
            movie_id=id,
            user_id=session['user_id']
        )
        db.session.add(comment)
        flash('评论成功', 'ok')
        movie.commentnum += 1
        db.session.add(movie)
        db.session.commit()

        return redirect(url_for('home.video', id=id))

    movie.playnum += 1
    db.session.add(movie)
    db.session.commit()

    return render_template("home/video.html", movie=movie, form=form, comment=comment)

# 弹幕
@home.route("/tm/", methods=["GET", "POST"])
def tm():
    import json
    # 获取弹幕
    if request.method == "GET":
        #获取弹幕消息队列
        id = request.args.get('id')
        key = "movie" + str(id)     # 存入redis时的key
        if rd.llen(key):
            msgs = rd.lrange(key, 0, 2999)
            res = {
                "code": 1,
                "danmaku": [json.loads(v) for v in msgs]
            }
        else:
            res = {
                "code": 1,
                "danmaku": []
            }
        resp = json.dumps(res)

    # 添加弹幕
    if request.method == "POST":
        data = json.loads(request.get_data())       # request.get_data获取请求的原始字符串
        msg = {
            "__v": 0,
            "author": data["author"],
            "time": data["time"],
            "text": data["text"],
            "color": data["color"],
            "type": data['type'],
            "ip": request.remote_addr,
            "_id": datetime.now().strftime("%Y%m%d%H%M%S") + uuid.uuid4().hex,
            "player": [
                data["player"]
            ]
        }
        res = {
            "code": 1,
            "data": msg
        }
        resp = json.dumps(res)
        rd.lpush("movie" + str(data["player"]), json.dumps(msg))
    return Response(resp, mimetype='application/json')

