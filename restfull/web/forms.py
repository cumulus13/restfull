from django import forms
from django.forms import Textarea, ModelForm
from . models import VIS_UserLogin


class EditUserForm(ModelForm):
	#UserNameLogin
	#PasswordLogin
	#NamaVendor
	#KodeVendor
	#HasChangePassword
	#Status
	#Priv
    class Meta:
        model = VIS_UserLogin
        fields =  '__all__'