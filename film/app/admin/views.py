from . import admin
from flask import render_template, redirect, url_for, session, request, flash, abort
from app.admin.forms import LoginForm, TagForm, MovieForm, PreviewForm, PwdForm, AuthForm, RoleForm, AdminForm
from app.models import Admin, Tag, Movie, Preview, User, Comment, Moviecol, Oplog, Adminlog, Userlog, Auth, Role
import functools
from app import db, app
# from werkzeug.utils import secure_filename          # 加密文件名称
import os
import uuid
from datetime import datetime
from werkzeug.security import generate_password_hash

# 定义上下文管理器
@admin.context_processor
def tpl_extra():
    data = dict(
        online_time=datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    )
    return data

# 定义登陆装饰器
def admin_login_required(view_func):
    @functools.wraps(view_func)       # functools.wraps装饰器可以解决因为添加装饰器而造成的函数属性改变，如__name__,__doc__等
    def wrapper(*args, **kwargs):
        if session.get("admin") is not None:     # 如果有对应session则已登陆
            return view_func(*args, **kwargs)
        else:
            return redirect(url_for('admin.login', next=request.url))
    return wrapper

# 定义修改文件名称的方法
def change_filename(filename):
    file_info = os.path.splitext(filename)
    # print(file_info[-1])
    filename = datetime.now().strftime("%Y%m%d") + str(uuid.uuid4().hex) + file_info[-1]
    return filename

# 定义权限装饰器
def admin_auth(view_func):
    @functools.wraps(view_func)    # 装饰器可以解决因为添加装饰器而造成的函数属性改变，如__name__
    def inner_func(*args, **kwargs):
        admin = Admin.query.join(
            Role
        ).filter(
            Role.id == Admin.role_id,
            Admin.id == session['admin_id'] 
        ).first()
        auths = admin.role.auths        # 获取登陆账户的权限（string）
        auths = list(map(lambda x: int(x), auths.split(",")))       # 获取登陆账户的权限(list)
        auth_list = Auth.query.all()    # 获取所有权限的列表
        urls = [v.url for v in auth_list for val in auths if val == v.id]   # 遍历两个列表，取出权限url
        rule = str(request.url_rule)         # 当前页面的url
        # print(rule)
        # print(urls)
        # print(str(rule) in urls)
        if rule not in urls:
            abort(404)
        return view_func(*args, **kwargs)
    return inner_func


# 首页
@admin.route("/")
@admin_login_required
def index():
    return render_template("admin/index.html")

# 登陆页面
@admin.route("/login", methods=['GET', 'POST'])
def login():
    form = LoginForm()      # 实例化一个表单对象
    # 如果是提交，验证信息
    if form.validate_on_submit():
        data = form.data
        admin = Admin.query.filter_by(name=data["username"]).first()
        if not admin.check_pwd(data['pwd']):
            flash('密码错误', 'err')
            return redirect(url_for('admin.login'))
        else:
            session["admin"] = data["username"]
            session['admin_id'] = admin.id
            # 添加登陆日志
            adminlog = Adminlog(
                admin_id=admin.id,
                ip=request.headers['X-Forwarded-For'], 
            )
            db.session.add(adminlog)
            db.session.commit()
            return redirect(request.args.get("next") or url_for("admin.index"))

    return render_template("admin/login.html", form=form)

# 登出页面， 定向到登陆页面
@admin.route("/logout")
@admin_login_required
def logout():
    session.clear()
    return redirect(url_for("admin.login"))

# 修改密码
@admin.route("/pwd", methods=['GET', 'POST'])
@admin_login_required
def pwd():
    form = PwdForm()

    if form.validate_on_submit():
        # 旧密码验证在表单内
        data = form.data
        admin = Admin.query.filter_by(name=session['admin']).first_or_404()
        admin.pwd = generate_password_hash(data['new_pwd'])
        db.session.add(admin)
        db.session.commit()
        flash('修改密码成功, 请重新登陆', 'ok')
        return redirect(url_for('admin.login'))

    return render_template("admin/pwd.html", form=form)



# 标签添加
@admin.route("/tag/add", methods=['GET', 'POST'])
@admin_login_required
@admin_auth
def tag_add():
    form = TagForm()
    # 如果提交表单
    if form.validate_on_submit():
        data = form.data
        # 校验参数
        tag = Tag.query.filter_by(name=data.get("name")).count()
        if tag == 1:    # 标签已经存在
            flash("标签已存在", 'err')
            return redirect(url_for('admin.tag_add'))
        else:   # 保存标签
            tag = Tag()
            tag.name = data["name"]
            db.session.add(tag)
            flash("添加标签成功", 'ok')
            # 添加操作日志
            oplog = Oplog(
                admin_id=session['admin_id'],
                ip=request.remote_addr,
                reason='添加一个标签: {}'.format(tag.name)
            )
            db.session.add(oplog)
            db.session.commit()
            return redirect(url_for("admin.tag_add"))
    return render_template('admin/tagadd.html', form=form)


# 标签列表
@admin.route("/tag/list/<int:page>", methods=['GET'])
@admin_login_required
@admin_auth
def tag_list(page=None):
    if page == None:
        page = 1
    page_data = Tag.query.order_by(Tag.id).paginate(page=page, per_page=10)
    return render_template('admin/taglist.html', page_data=page_data)


# 标签删除
@admin.route("/tag/del/<int:id>", methods=['GET'])
@admin_login_required
@admin_auth
def tag_del(id=None):
    tag = Tag.query.filter_by(id=id).first_or_404()     # first_or_404() 如果没找到弹出404
    db.session.delete(tag)
    # 添加操作日志
    oplog = Oplog(
        admin_id=session['admin_id'],
        ip=request.remote_addr,
        reason='删除一个标签: {}'.format(tag.name)
    )
    db.session.add(oplog)
    db.session.commit()
    flash("删除标签成功", 'ok')
    return redirect(url_for('admin.tag_list', page=1))


# 编辑标签
@admin.route("/tag/edit/<int:id>", methods=['GET', 'POST'])
@admin_login_required
@admin_auth
def tag_edit(id):
    form = TagForm()
    tag = Tag.query.get_or_404(id)

    # 如果提交表单(修改)
    if form.validate_on_submit():
        data = form.data
        # 校验参数
        new_tag = Tag.query.filter_by(name=data.get("name")).count()
        if tag.name == data['name'] or new_tag == 1:    # 标签已经存在
            flash("未修改标签名or标签已存在", 'err')
            return redirect(url_for('admin.tag_edit', id=id))
        else:   # 保存标签
            tag.name = data["name"]
            db.session.add(tag)
            db.session.commit()
            flash("修改标签成功", 'ok')
            return redirect(url_for("admin.tag_edit", id=id))

    return render_template('admin/tag_edit.html', form=form, tag=tag)


# 电影添加
@admin.route("/movie/add", methods=['GET', 'POST'])
@admin_login_required
@admin_auth
def movie_add():
    form = MovieForm()
    # 如果是提交表单
    if form.validate_on_submit():
        data = form.data
        movie_count = Movie.query.filter_by(title=data['title']).count()
        if movie_count == 1:
            flash("电影名已存在", 'err')
            return redirect(url_for("admin.movie_add"))
        else:
            file_url = form.url.data.filename       # 获取文件名
            file_logo = form.logo.data.filename
            if not os.path.exists(app.config['UP_DIR']):        # 如果不存在设置的存放目录
                os.mkdirs(app.config['UP_DIR'])             # 创建存放目录
                os.chmod(app.config['UP_DIR'], 'rw')           # 修改存放目录的权限 rw
            url = change_filename(file_url)         # 格式化文件名
            logo = change_filename(file_logo)
            # 将文件保存到存放目录
            form.url.data.save(app.config['MOVIES_DIR'] + url)
            form.logo.data.save(app.config['MOVIES_DIR'] + logo)
            movie = Movie(
                title=data["title"],
                url=url,
                info=data["info"],
                logo=logo,
                star=int(data["star"]),
                playnum=0,
                commentnum=0,
                tag_id=int(data["tag"]),
                area=data["area"],
                release_time=data["release_time"],
                length=data["length"],
            )
            db.session.add(movie)
            db.session.commit()
            flash("添加电影成功", "ok")
            return redirect(url_for("admin.movie_add"))
    return render_template('admin/movieadd.html', form=form)


# 电影列表
@admin.route("/movie/list/<int:page>", methods=['GET'])
@admin_login_required
@admin_auth
def movie_list(page=None):
    if page is None:
        page = 1
    page_data = Movie.query.join(Tag).order_by(Movie.id).paginate(page=page, per_page=10, error_out=False)
    return render_template('admin/movielist.html', page_data=page_data)


# 删除电影
@admin.route("/movie/del/<int:id>", methods=['GET'])
@admin_login_required
@admin_auth
def movie_del(id):
    movie = Movie.query.get_or_404(int(id))
    db.session.delete(movie)
    db.session.commit()
    flash("删除成功", 'ok')
    return redirect(url_for("admin.movie_list", page=1))

# 编辑电影
@admin.route("/movie/edit/<int:id>", methods=["GET", 'POST'])
@admin_login_required
@admin_auth
def movie_edit(id=None):
    form = MovieForm()
    # 消除表单中usrl和logo选择框的必填属性
    form.url.validators = []
    form.logo.validators = []

    movie = Movie.query.get_or_404(int(id))
    if request.method == 'GET':
        # 以下三个选择框/Text框不能通过模板获取默认值，所以使用原生方法设置默认值
        form.info.data = movie.info
        form.star.data = movie.star
        form.tag.data = movie.tag_id
        return render_template('admin/movie_edit.html', form=form, movie=movie)

    # 如果是提交表单
    if form.validate_on_submit():
        data = form.data
        movie_count = Movie.query.filter_by(title=data['title']).count()
        if movie_count == 1 and data['title'] != movie.title:
            flash("电影名已存在", 'err')
            return redirect(url_for("admin.movie_edit", id=id))
        else:
            # 如果表单的url框不为空，表示修改了url
            # print(form.url.data.filename)
            if form.url.data.filename != '':
                file_url = form.url.data.filename       # 获取文件名
                url = change_filename(file_url)         # 格式化文件名
                form.url.data.save(app.config['MOVIES_DIR'] + url)      # 将文件保存到目录
                movie.url = url     # 把文件名保存到数据库

            if form.logo.data.filename != '':
                file_logo = form.logo.data.filename         # 获取文件名
                logo = change_filename(file_logo)       # 格式化文件名
                form.logo.data.save(app.config['MOVIES_DIR'] + logo)   # 将文件保存到存放目录
                movie.logo = logo       # 把文件名保存到数据库

            movie.title = data["title"]
            movie.info = data["info"]
            movie.star = int(data["star"])
            movie.tag_id = int(data["tag"])
            movie.area = data["area"]
            movie.release_time = data["release_time"]
            movie.length = data["length"]

            db.session.add(movie)
            db.session.commit()
            flash("添加电影成功", "ok")
            return redirect(url_for("admin.movie_edit", id=id))

    if request.method == 'POST':
        # 当提交数据的时候,必填字段没有输入,但是有post请求
        form.info.data = movie.info
        form.star.data = movie.star
        form.tag.data = movie.tag_id
        flash("请输入必填字段", 'err')
        return render_template('admin/movie_edit.html', form=form, movie=movie)


# 预告添加
@admin.route("/preview/add", methods=['GET', 'POST'])
@admin_login_required
@admin_auth
def preview_add():
    form = PreviewForm()

    # 提交
    if form.validate_on_submit():
        data = form.data
        # 校验参数(如果标题重复)
        preview_count = Preview.query.filter_by(title=data['title']).count()
        if preview_count == 1:
            flash("该标题已存在", 'err')
            return redirect(url_for('admin.preview_add'))
        
        # 保存logo文件
        file_logo = form.logo.data.filename       # 获取文件名
        logo = change_filename(file_logo)         # 格式化文件名
        form.logo.data.save(app.config['PREVIEWS_DIR'] + logo)      # 将文件保存到目录

        preview = Preview(
            title=data['title'],
            logo=logo
        )
        
        db.session.add(preview)
        db.session.commit()
        flash("添加成功", 'ok')
        return redirect(url_for("admin.preview_add"))
        

    return render_template('admin/previewadd.html', form=form)


# 预告列表
@admin.route("/preview/list/<int:page>", methods=['GET'])
@admin_login_required
@admin_auth
def preview_list(page=None):
    if page == None:
        page = 1
    page_data = Preview.query.order_by(Preview.id).paginate(page=page, per_page=10, error_out=False)
    return render_template('admin/previewlist.html', page_data=page_data)


# 预告删除
@admin.route("/preview/del/<int:id>", methods=['GET'])
@admin_login_required
@admin_auth
def preview_del(id):
    preview = Preview.query.get_or_404(int(id))
    db.session.delete(preview)
    db.session.commit()
    flash("删除成功", 'ok')
    return redirect(url_for("admin.preview_list", page=1))


# 预告编辑
@admin.route("/preview/edit/<int:id>", methods=['GET', 'POST'])
@admin_login_required
@admin_auth
def preview_edit(id):
    form = PreviewForm()
    form.logo.validators = []      # 置空选择框的必填属性
    preview = Preview.query.get_or_404(int(id))

    # 如果是提交数据
    if form.validate_on_submit():
        data = form.data
        
        # 如果修改的标题重复了
        preview_count = Preview.query.filter_by(title=data["title"]).count()
        if preview_count == 1 and preview.title != data['title']:
            flash("该预告标题已存在", 'err')
            return redirect(url_for("admin.preview_edit", id=id))

        # 如果有修改预告图片
        if form.logo.data.filename != '':
            file_logo = form.logo.data.filename       # 获取文件名
            logo = change_filename(file_logo)         # 格式化文件名
            form.logo.data.save(app.config['PREVIEWS_DIR'] + logo)      # 将文件保存到目录
            preview.logo = logo     # 把文件名保存到数据库

        preview.title = data['title']       # 保存标题
        db.session.add(preview)
        db.session.commit()

        flash("修改成功", 'ok')
        return redirect(url_for("admin.preview_edit", id=id)) 

    return render_template("admin/preview_edit.html", form=form, preview=preview)



# 用户列表
@admin.route("/user/list/<int:page>")
@admin_login_required
@admin_auth
def user_list(page=None):
    if page == None:
        page = 1
    page_data = User.query.order_by(User.id).paginate(page=page, per_page=10, error_out=False)
    return render_template("admin/userlist.html", page_data=page_data)


# 用户查看
@admin.route("/user/view/<int:id>", methods=['GET'])
@admin_login_required
@admin_auth
def user_view(id):
    user = User.query.get_or_404(int(id))
    return render_template("admin/userview.html", user=user)

# 用户删除
@admin.route("/user/del/<int:id>", methods=['GET'])
@admin_login_required
@admin_auth
def user_del(id):
    user = User.query.get_or_404(int(id))
    db.session.delete(user)
    db.session.commit()
    flash("删除成功", "ok")
    return redirect(url_for('admin.user_list', page=1))


# 评论列表
@admin.route("/comment/list/<int:page>/", methods=['GET'])
@admin_login_required
@admin_auth
def comment_list(page=None):
    if page == None:
        page = 1
    page_data = Comment.query.order_by(Comment.id).paginate(page=page, per_page=10, error_out=False)
    return render_template("admin/comment_list.html", page_data=page_data)

# 评论删除
@admin.route("/comment/del/<int:id>", methods=['GET'])
@admin_login_required
@admin_auth
def comment_del(id):
    comment = Comment.query.get_or_404(int(id))
    db.session.delete(comment)
    db.session.commit()
    flash("操作成功", 'ok')
    return redirect(url_for('admin.comment_list', page=1))



# 收藏列表
@admin.route("/moviecol/list/<int:page>", methods=['GET'])
@admin_login_required
@admin_auth
def moviecol_list(page=None):
    if page == None:
        page = 1 
    page_data = Moviecol.query.order_by(Moviecol.add_time).paginate(page=page, per_page=10, error_out=False)
    return render_template("admin/moviecol_list.html", page_data=page_data)

# 收藏删除
@admin.route("/moviecol/del/<int:id>", methods=['GET'])
@admin_login_required
@admin_auth
def moviecol_del(id):
    moviecol = Moviecol.query.get_or_404(int(id))
    db.session.delete(moviecol)
    db.session.commit()
    flash('删除成功', 'ok')
    return redirect(url_for('admin.moviecol_list', page=1))



# 操作日志列表
@admin.route("/oplog/list/<int:page>")
@admin_login_required
def oplog_list(page=None):
    if page == None:
        page = 1
    page_data = Oplog.query.join(
            Admin
        ).filter(
            Oplog.admin_id==Admin.id
        ).order_by(
            Oplog.add_time.desc()
        ).paginate(
            page=page, per_page=10, error_out=False
        )
    return render_template("admin/oplog_list.html", page_data=page_data)

# 管理员登陆日志
@admin.route("/adminlog/list/<int:page>")
@admin_login_required
def adminlog_list(page=None):
    if page == None:
        page = 1
    page_data = Adminlog.query.join(
        Admin
    ).filter(
        Admin.id==Adminlog.admin_id
    ).order_by(
        Adminlog.add_time.desc()
    ).paginate(page=1, per_page=10, error_out=False)
    return render_template("admin/adminlog_list.html", page_data=page_data)

# 用户登陆日志
@admin.route("/userlog/list/<int:page>")
@admin_login_required
def userlog_list(page=None):
    if page == None:
        page = 1
    page_data = Userlog.query.order_by(Userlog.add_time.desc()).paginate(page=1, per_page=10, error_out=False)
    return render_template("admin/userlog_list.html", page_data=page_data)


# 权限添加
@admin.route("/auth/add", methods=['GET', 'POST'])
@admin_login_required
@admin_auth
def auth_add():
    form = AuthForm()

    if form.validate_on_submit():
        data=form.data
        # 如果权限名称重复
        auth_count = Auth.query.filter_by(name=data['name']).count()
        if auth_count == 1:
            flash("该权限名已存在", 'err')
            return redirect(url_for('admin.auth_add'))

        auth = Auth(
            name=data['name'],
            url=data['url']
        )
        db.session.add(auth)
        db.session.commit()
        flash('添加权限成功', 'ok')
        return redirect(url_for('admin.auth_add'))


    return render_template('admin/auth_add.html', form=form)

# 权限列表
@admin.route("/auth/list/<int:page>")
@admin_login_required
@admin_auth
def auth_list(page=None):
    if page == None:
        page = 1
    page_data = Auth.query.order_by(Auth.id).paginate(page=page, per_page=10, error_out=False)
    return render_template("admin/auth_list.html", page_data=page_data)

# 删除权限
@admin.route("/auth/del/<int:id>", methods=['GET'])
@admin_login_required
@admin_auth
def auth_del(id):
    auth = Auth.query.get_or_404(int(id))
    db.session.delete(auth)
    db.session.commit()
    flash("删除权限成功", 'ok')
    return redirect(url_for("admin.auth_list", page=1))

# 修改权限
@admin.route("/auth/edit/<int:id>", methods=['GET', 'POST'])
@admin_login_required
@admin_auth
def auth_edit(id):
    form = AuthForm()
    auth = Auth.query.get_or_404(int(id))

    if form.validate_on_submit():
        data = form.data

        # 如果权限名称重复
        auth_count = Auth.query.filter_by(name=data['name']).count()
        if auth_count == 1 and auth.name != data['name']:
            flash('权限名已存在', 'err')
            return redirect(url_for("admin.auth_edit", id=id))
        
        auth.name = data['name']
        auth.url = data['url']
        db.session.add(auth)
        db.session.commit()
        flash("修改权限成功", 'ok')
        return redirect(url_for("admin.auth_edit", id=id))

    return render_template('admin/auth_edit.html', form=form, auth=auth)



# 角色添加
@admin.route("/role/add", methods=['GET', 'POST'])
@admin_login_required
@admin_auth
def role_add():
    form = RoleForm()
    auth = Auth.query.all()

    if form.validate_on_submit():
        data = form.data

        # 如果角色名重复
        role_count = Role.query.filter_by(name=data['name']).count()
        if role_count == 1:
            flash('角色名已存在', 'err')
            return redirect(url_for('admin.role_add')) 
        
        role = Role(
            name=data['name'],
            auths=','.join(map(lambda x: str(x), data['auth']))
        )
        db.session.add(role)
        db.session.commit()
        flash('创建角色成功', 'ok')
        return redirect(url_for('admin.role_add')) 

    return render_template('admin/role_add.html', form=form, auth=auth)

# 角色列表
@admin.route("/role/list/<int:page>", methods=['GET'])
@admin_login_required
@admin_auth
def role_list(page=None):
    if page == None:
        page = 1
    page_data = Role.query.order_by(Role.add_time).paginate(page=page, per_page=10, error_out=False)
    return render_template("admin/role_list.html", page_data=page_data)

# 删除角色
@admin.route("/role/del/<int:id>", methods=['GET'])
@admin_login_required
@admin_auth
def role_del(id):
    role = Role.query.get(int(id))
    db.session.delete(role)
    db.session.commit()
    flash('删除角色成功', 'ok')
    return redirect(url_for("admin.role_list", page=1))

# 编辑角色
@admin.route("/role/edit/<int:id>", methods=['GET', 'POST'])
@admin_login_required
@admin_auth
def role_edit(id):
    form = RoleForm()
    role = Role.query.get(int(id))

    # 根据role渲染多选框的默认值
    if request.method == 'GET':
        auths = role.auths
        form.auth.data = list(map(lambda x: int(x), auths.split(",")))


    # 如果是提交修改
    if form.validate_on_submit():
        data = form.data

        # 如果角色名重复
        role_count = Role.query.filter_by(name=data['name']).count()
        if role_count == 1 and role.name != data['name']:
            flash('该角色名已存在', 'err')
            return redirect(url_for('admin.role_edit', id=id))

        role.name = data['name']
        role.auths = ",".join(map(lambda x: str(x), data['auth']))
        db.session.add(role)
        db.session.commit()
        flash('修改角色成功', 'ok')
        return redirect(url_for('admin.role_edit', id=id))
    return render_template('admin/role_edit.html', form=form, role=role)



# 添加管理员
@admin.route("/admin/add", methods=['GET', 'POST'])
@admin_login_required
@admin_auth
def admin_add():
    form = AdminForm()

    if form.validate_on_submit():
        data = form.data

        # 如果管理员名称已存在
        admin_count = Admin.query.filter_by(name=data['name']).count()
        if admin_count == 1:
            flash('该管理员名称已存在', 'err')
            return redirect(url_for('admin.admin_add'))

        # 保存数据库
        admin = Admin(
            name=data['name'],
            pwd=generate_password_hash(data['pwd']),
            role_id=data['role'],
            is_super=False,
        )
        db.session.add(admin)
        db.session.commit()
        flash("添加管理员成功", 'ok')
        return redirect(url_for('admin.admin_add'))

    return render_template("admin/admin_add.html", form=form)

# 管理员列表
@admin.route("/admin/list/<int:page>")
@admin_login_required
@admin_auth
def admin_list(page=None):
    if page == None:
        page = 1
    page_data = Admin.query.order_by(Admin.id).paginate(page=page, per_page=10, error_out=False)
    return render_template("admin/admin_list.html", page_data=page_data)




