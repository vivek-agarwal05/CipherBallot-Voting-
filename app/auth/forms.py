"""
app/auth/forms.py — WTForms form definitions for authentication.
"""
from flask_wtf import FlaskForm
from wtforms import BooleanField, PasswordField, StringField, SubmitField, SelectField
from wtforms.validators import DataRequired, Length, Regexp, EqualTo, Email


class LoginForm(FlaskForm):
    """
    Voter / admin login form.

    Validation is intentionally minimal client-side: the server always gives
    generic error messages that do not reveal whether a username exists.
    """
    username = StringField(
        'Username',
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
            'placeholder': 'your_username',
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
      3. Academic department criteria validation.
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

    department = SelectField(
        'Academic Department',
        choices=[
            ('CS Department', 'Computer Science Department'),
            ('Information Security', 'Information Security & Cyber Forensics'),
            ('Data Science', 'Data Science & Artificial Intelligence'),
            ('ECE Department', 'Electronics & Comm Department'),
        ],
        validators=[DataRequired(message='Department selection is required.')],
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
