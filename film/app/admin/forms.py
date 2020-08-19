from flask_wtf import FlaskForm
from wtforms import SubmitField, StringField, PasswordField, FileField, TextAreaField, SelectField, SelectMultipleField
from wtforms.validators import DataRequired, ValidationError, EqualTo
from app.models import Tag
from app.models import Admin, Auth, Role

tags = Tag.query.all()
auth_list = Auth.query.all()
role_list = Role.query.all()

# 登陆表单
class LoginForm(FlaskForm):
    username = StringField(
        label='用户名',
        validators=[DataRequired('请输入账号')],
        render_kw={          # 添加表单框中的样式
            "class": "form-control",
            "placeholder": "请输入账号！",
        }
    )
    pwd = PasswordField(
        label='密码',
        validators=[DataRequired("请输入密码")],
        render_kw={
            "class": "form-control",
            "placeholder": "请输入密码！",
        }
    )
    submit = SubmitField(
        "登陆",
        render_kw={
            "class": "btn btn-primary btn-block btn-flat"    
        }
    )

    # 自定义表单验证器
    def validate_username(self, field):
        username = field.data
        from app.models import Admin     # 在这里使用时导入，方式循环导入
        admin = Admin.query.filter_by(name=username).count()
        if admin == 0:
            raise ValidationError("账号不存在")

# 修改密码
class PwdForm(FlaskForm):
    old_pwd = PasswordField(
        label='旧密码',
        validators=[DataRequired('请填写旧密码')],
        description='旧密码',
        render_kw={
            "class": "form-control",
            "id": "input_pwd",
            "placeholder": "请输入旧密码！"
        }
    )
    new_pwd = PasswordField(
        label='新密码',
        validators=[DataRequired('请输入新密码')],
        description='新密码',
        render_kw={
            "class": "form-control",
            "id": "input_pwd",
            "placeholder": "请输入新密码！"
        }
    )
    submit = SubmitField(
        '修改',
        render_kw={
            "class": "btn btn-primary"
        }
    )

    # 验证旧密码
    def validate_old_pwd(self, field):
        from flask import session
        pwd = field.data
        name = session['admin']
        admin = Admin.query.filter_by(name=name).first_or_404()
        if not admin.check_pwd(pwd):
            raise ValidationError('旧密码错误！')


# 添加标签的表单
class TagForm(FlaskForm):
    name = StringField(
        label='标签名称',
        validators=[DataRequired('请填写标签名称')],
        description='标签',
        render_kw={
            "class": "form-control",
            "id": "input_name",
            "placeholder": "请输入标签名称！",
        }
    )
    submit = SubmitField(
        '编辑',
        render_kw={
            "class": "btn btn-primary"
        }
    )


# 添加电影表单
class MovieForm(FlaskForm):
    title = StringField(        # 片名
        label='片名',
        validators=[DataRequired('请输入片名')],
        description='片名',
        render_kw={
            "class": "form-control",
            "id": "input_title",
            "placeholder": "请输入片名！",
        }
    )

    url = FileField(        # 选择文件
        label='文件',
        validators=[DataRequired('请选择文件')],
        description='文件',
    )

    info = TextAreaField(       # 简介
        label='简介',
        validators=[DataRequired('请输入简介')],
        description='简介',
        render_kw={
            "class": "form-control",
            "rows": 10,
            "placeholder": "请输入简介！",
            "id": "input_info"
        }
    )

    logo = FileField(   # 封面
        label='封面',
        validators=[DataRequired('请上传封面')],
        description='封面',
    )

    star = SelectField(     # 星级
        label='星级',
        validators=[DataRequired('请选择星级')],
        description='星级',
        coerce=int,
        choices=[(1, "一星"), (2, "二星"), (3, "三星"), (4, "四星"), (5, "五星")],
        render_kw={
            "class": "form-control",
            "id": "input_star",
        }
    )

    tag = SelectField(      # 标签
        label='标签',
        validators=[DataRequired('请选择标签')],
        description='标签',
        coerce=int,
        choices=[(v.id, v.name) for v in tags],
        render_kw={
            "class": "form-control",
            "id": "input_tag_id",
        }
    )

    area = StringField(     # 地区
        label='地区',
        validators=[DataRequired('请输入地区')],
        description='地区',
        render_kw={
            "class": "form-control",
            "id": "input_area",
            "placeholder": "请输入地区！",
        }
    )

    length = StringField(     # 片长
        label='片长',
        validators=[DataRequired('请输入片长')],
        description='片场',
        render_kw={
            "class": "form-control",
            "id": "input_length",
            "placeholder": "请输入片长！",
        }
    )

    release_time = StringField(     # 上映时间
        label='上映时间',
        validators=[DataRequired('请输入上映时间')],
        description='上映时间',
        render_kw={
            "class": "form-control",
            "id": "input_release_time",
            "placeholder": "请输入上映时间！",
        }
    )

    submit = SubmitField(       # 提交
        '添加',
        render_kw={
            "class": "btn btn-primary"
        }
    )

# 添加预告
class PreviewForm(FlaskForm):
    title = StringField(
        label='预告标题',
        validators=[DataRequired('请输入预告标题')],
        description='预告标题',
        render_kw={          # 添加表单框中的样式
            "class": "form-control",
            "id": "input_title",
            "placeholder": "请输入预告标题！",
        }
    )
    logo = FileField(
        label='预告封面',
        validators=[DataRequired('请选择预告封面')],
        description='预告封面',
        render_kw={
            "id": "input_logo"
        }
    )
    submit = SubmitField(
        '提交',
        render_kw={
           "class": "btn btn-primary" 
        }
    )

# 添加权限
class AuthForm(FlaskForm):
    name = StringField(
        label='权限名称',
        validators=[DataRequired('请输入权限名称')],
        description="权限名称",
        render_kw={
            "class": "form-control",
            "id": "input_name",
            "placeholder": "请输入权限名称！",
        }
    )
    url = StringField(
        label='权限地址',
        validators=[DataRequired('请输入权限地址')],
        description='权限地址',
        render_kw={
            "class": "form-control",
            "id": "input_url",
            "placeholder": "请输入权限地址！"
        }
    )
    submit = SubmitField(
        '添加',
        render_kw={
            "class": "btn btn-primary"
        }
    )

# 添加角色
class RoleForm(FlaskForm):
    name = StringField(
        label='角色名称',
        validators=[DataRequired('请输入角色名称')],
        description='角色名称',
        render_kw={
            "class": "form-control",
            "id": "input_name",
            "placeholder": "请输入角色名称！"
        }
    )
    auth = SelectMultipleField(
        label='操作权限',
        validators=[DataRequired('请选择权限')],
        description='操作权限',
        coerce=int,
        choices=[(v.id, v.name) for v in auth_list],
        render_kw={
            "class": "form-control",
        }
    )
    submit = SubmitField(
        '添加',
        render_kw={
            "class": "btn btn-primary"
        }
    )

# 添加管理员
class AdminForm(FlaskForm):
    name = StringField(
        label='管理员名称',
        validators=[DataRequired('请输入管理员名称')],
        description='管理员名称',
        render_kw={
            "class": "form-control",
            "id": "input_name",
            "placeholder": "请输入管理员名称！"
        }
    )
    pwd = PasswordField(
        label='管理员密码',
        validators=[DataRequired("请输入管理员密码")],
        description="管理员密码",
        render_kw={
            "class": "form-control",
            "id": "input_pwd",
            "placeholder": "请输入管理员密码！"
        }
    )
    re_pwd = PasswordField(
        label='管理员重复密码',
        validators=[
            DataRequired("请输入管理员重复密码"),
            EqualTo('pwd', '两次密码输入不一致'),
        ],
        description="管理员重复密码",
        render_kw={
            "class": "form-control",
            "id": "input_re_pwd",
            "placeholder": "请输入管理员重复密码！"
        }
    )
    role = SelectField(
        label='所属角色',
        validators=[DataRequired("请选择角色")],
        description="所属角色",
        coerce=int,
        choices=[(v.id, v.name) for v in role_list],
        render_kw={
            "class": "form-control",
        }
    )
    submit = SubmitField(
        '添加',
        render_kw={
            "class": "btn btn-primary"
        }
    )


