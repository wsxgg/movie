from flask_wtf import FlaskForm
from wtforms.fields import StringField, PasswordField, SubmitField, FileField, TextAreaField
from wtforms.validators import DataRequired, EqualTo, Email, Regexp, ValidationError
from app.models import User


# 会员注册表单
class RegistForm(FlaskForm):
    name = StringField(
        label='用户昵称',
        validators=[DataRequired('请输入用户昵称')],
        description='用户昵称',
        render_kw={
            "id": "input_name",
            "class": "form-control input-lg",
            "placeholder": "昵称"
        }
    )
    email = StringField(
        label='邮箱',
        validators=[
            DataRequired('请输入用户邮箱'),
            Email('邮箱格式不正确')
        ],
        description='邮箱',
        render_kw={
            "id": "input_email",
            "class": "form-control input-lg",
            "placeholder": "邮箱"
        }
    )
    phone = StringField(
        label='电话',
        validators=[
            DataRequired('请输入电话'),
            Regexp(r"1[3458]\d{9}", message='手机格式不正确')
        ],
        description='电话',
        render_kw={
            "id": "input_phone",
            "class": "form-control input-lg",
            "placeholder": "电话"
        }
    )
    pwd = PasswordField(
        label='密码',
        validators=[DataRequired('请输入用户密码')],
        description='密码',
        render_kw={
            "id": "input_password",
            "class": "form-control input-lg",
            "placeholder": "密码"
        }
    )
    repwd = PasswordField(
        label='确认密码',
        validators=[
            DataRequired('请输入确认密码'),
            EqualTo("pwd", '两次密码不一致')
        ],
        description='确认密码',
        render_kw={
            "id": "input_repassword",
            "class": "form-control input-lg",
            "placeholder": "确认密码"
        }
    )
    submit = SubmitField(
        '注册',
        render_kw={
            "class": "btn btn-lg btn-success btn-block"
        }
    )

    # 自定义昵称验证
    def validate_name(self, field):
        name = field.data
        user_count = User.query.filter_by(name=name).count()
        if user_count == 1:
            raise ValidationError('名称已存在')
    # 自定义email验证
    def validate_email(self, field):
        email = field.data
        user_count = User.query.filter_by(email=email).count()
        if user_count == 1:
            raise ValidationError('邮箱已注册')
    # 自定义phone验证
    def validate_phone(self, field):
        phone = field.data
        user_count = User.query.filter_by(phone=phone).count()
        if user_count == 1:
            raise ValidationError('手机已注册')

# 会员登陆表单
class LoginForm(FlaskForm):
    name = StringField(
        label='账号',
        validators=[DataRequired('请输入账号')],
        description='账号',
        render_kw={
            "id": "input_contact",
            "class": "form-control input-lg",
            "placeholder": "用户名/邮箱/手机号码",
            "autofocus": "autofocus"
        }
    )
    pwd = PasswordField(
        label='密码',
        validators=[DataRequired("请输入密码")],
        description='密码',
        render_kw={
            "id": "input_password",
            "class": "form-control input-lg",
            "placeholder": "密码",
        }
    )
    submit = SubmitField(
        '登陆',
        render_kw={
            "class": "btn btn-lg btn-success btn-block"
        }
    )

# 会员信息表单
class UserDetailForm(FlaskForm):
    name = StringField(
        label='昵称',
        validators=[DataRequired('请填写昵称')],
        render_kw={
            "class": "form-control",
            "id": "input_name",
            "placeholder": "昵称",

        }
    )
    email = StringField(
        label='邮箱',
        validators=[
            DataRequired('请输入用户邮箱'),
            Email('邮箱格式不正确')
        ],
        description='邮箱',
        render_kw={
            "id": "input_email",
            "class": "form-control",
            "placeholder": "邮箱"
        }
    )
    phone = StringField(
        label='手机',
        validators=[
            DataRequired('请输入手机号码'),
            Regexp(r"1[3458]\d{9}", message='手机格式不正确')
        ],
        description='手机',
        render_kw={
            "id": "input_phone",
            "class": "form-control",
            "placeholder": "手机"
        }
    )
    face = FileField(
        label='头像',
        description="头像"
    )
    info = TextAreaField(
        label='简介',
        render_kw={
            'class': "form-control",
            "rows": 10,
            "id": "input_info"
        }
    )
    submit = SubmitField(
        '保存',
        render_kw={
            "class": "btn btn-success"
        }
    )

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
        '修改密码',
        render_kw={
            "class": "btn btn-success"
        }
    )

# 评论表单
class CommentForm(FlaskForm):
    content = TextAreaField(
        label='内容',
        validators=[DataRequired('请填写内容')],
        description='内容',
        render_kw={
            "id": "input_content",
        }
    )

    submit = SubmitField(
        '提交评论',
        render_kw={
            "class": "btn btn-success",
            "id": "btn-sub"
        }
    )


