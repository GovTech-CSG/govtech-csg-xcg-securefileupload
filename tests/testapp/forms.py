# Form with just one field to upload a file
from django import forms

from govtech_csg_xcg.securefileupload.validators import xcg_file_validator


class TestForm(forms.Form):
    uploaded_file = forms.FileField(validators=[xcg_file_validator])
