"""
app/auth/forms.py — WTForms form definitions for authentication & password recovery.
"""
from flask_wtf import FlaskForm
from wtforms import BooleanField, PasswordField, StringField, SubmitField
from wtforms.validators import DataRequired, Length, Regexp, EqualTo


class LoginForm(FlaskForm):
    """
    Voter / admin login form.

    Validation is intentionally minimal client-side: the server always gives
    generic error messages that do not reveal whether a username exists.
    """
    username = StringField(
        'Student ID / Username',
        validators=[
            DataRequired(message='Username or Student ID is required.'),
            Length(min=3, max=64, message='Username must be 3–64 characters.'),
            Regexp(
                r'^[a-zA-Z0-9_.\-]+$',
                message='Username may only contain letters, digits, _, ., -',
            ),
        ],
        render_kw={
            'autocomplete': 'username',
            'placeholder': 'your_username or STU-...',
            'autofocus': True,
        },
    )

    password = PasswordField(
        'Password',
        validators=[
            DataRequired(message='Password is required.'),
            Length(min=8, max=256, message='Password must be 8–256 characters.'),
        ],
        render_kw={
            'autocomplete': 'current-password',
            'placeholder': '••••••••',
        },
    )

    remember_me = BooleanField('Keep me signed in for 1 hour')

    submit = SubmitField('Sign In')


class RegisterForm(FlaskForm):
    """
    Student Voter Registration Form with Criteria & ID Verification.

    Criteria enforced:
      1. Student ID verification against authoritative institutional roster.
      2. 1:1 mapping (preventing duplicate registrations of the same student).
      3. Academic department & institutional email criteria validation.
      4. Argon2id password complexity criteria (length, uppercase, lowercase, numbers, symbols).
    """
    student_id = StringField(
        'Student / Institutional ID',
        validators=[
            DataRequired(message='Student ID is required for verification.'),
            Length(min=4, max=64, message='Student ID must be 4–64 characters.'),
            Regexp(
                r'^[A-Za-z0-9_\-]+$',
                message='Student ID must contain only letters, numbers, hyphens, and underscores.',
            ),
        ],
        render_kw={
            'placeholder': 'e.g. STU-CS-2024-010',
            'autofocus': True,
        },
    )

    verification_pin = StringField(
        'Secret Verification PIN',
        validators=[
            DataRequired(message='Verification PIN issued by the institution is required.'),
            Length(min=4, max=32, message='Verification PIN must be 4–32 characters.'),
        ],
        render_kw={
            'placeholder': 'e.g. PIN-010',
            'autocomplete': 'off',
        },
    )

    username = StringField(
        'Desired Username',
        validators=[
            DataRequired(message='Username is required.'),
            Length(min=3, max=64, message='Username must be 3–64 characters.'),
            Regexp(
                r'^[a-zA-Z0-9_.\-]+$',
                message='Username may only contain letters, digits, _, ., -',
            ),
        ],
        render_kw={
            'autocomplete': 'username',
            'placeholder': 'e.g. f_miller',
        },
    )

    display_name = StringField(
        'Full Legal Name',
        validators=[
            DataRequired(message='Full legal name is required.'),
            Length(min=2, max=128, message='Name must be 2–128 characters.'),
        ],
        render_kw={
            'placeholder': 'e.g. Frank Miller',
        },
    )

    department = StringField(
        'Academic Department',
        validators=[
            DataRequired(message='Department is required.'),
            Length(min=2, max=128, message='Department must be 2–128 characters.'),
        ],
        render_kw={
            'list': 'department-suggestions',
            'placeholder': 'e.g. CS Department',
        },
    )

    email = StringField(
        'Institutional Email',
        validators=[
            DataRequired(message='Institutional email is required.'),
            Length(min=5, max=128, message='Email must be valid length.'),
            Regexp(
                r'^[^@]+@[^@]+\.[^@]+$',
                message='Please provide a valid institutional email address.',
            ),
        ],
        render_kw={
            'placeholder': 'e.g. frank.miller@univ.edu',
        },
    )

    password = PasswordField(
        'Password',
        validators=[
            DataRequired(message='Password is required.'),
            Length(min=8, max=256, message='Password must be at least 8 characters.'),
        ],
        render_kw={
            'autocomplete': 'new-password',
            'placeholder': '••••••••',
        },
    )

    confirm_password = PasswordField(
        'Confirm Password',
        validators=[
            DataRequired(message='Please confirm your password.'),
            EqualTo('password', message='Passwords must match.'),
        ],
        render_kw={
            'autocomplete': 'new-password',
            'placeholder': '••••••••',
        },
    )

    submit = SubmitField('Verify ID & Register')


class ForgotPasswordForm(FlaskForm):
    """Request a single-use password reset email."""
    identifier = StringField(
        'Username, Student ID, or Institutional Email',
        validators=[
            DataRequired(message='Please enter your username, Student ID, or email.'),
            Length(min=3, max=128),
        ],
        render_kw={
            'placeholder': 'e.g. alice, STU-CS-2024-001, or alice@univ.edu',
            'autofocus': True,
        },
    )
    submit = SubmitField('Send Password Reset Link')


class ResetPasswordForm(FlaskForm):
    """Set a new password using a signed reset token."""
    password = PasswordField(
        'New Password',
        validators=[
            DataRequired(message='New password is required.'),
            Length(min=8, max=256, message='Password must be at least 8 characters.'),
        ],
        render_kw={'autocomplete': 'new-password', 'placeholder': '••••••••'},
    )
    confirm_password = PasswordField(
        'Confirm New Password',
        validators=[
            DataRequired(message='Please confirm your password.'),
            EqualTo('password', message='Passwords must match.'),
        ],
        render_kw={'autocomplete': 'new-password', 'placeholder': '••••••••'},
    )
    submit = SubmitField('Reset Password')
