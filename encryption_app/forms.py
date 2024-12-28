from django import forms
from django.contrib.auth.models import User
from django.db.models import Q
from .models import UserRelation

class EncryptionForm(forms.Form):
    file = forms.FileField(label='Select a file')
    encryption_key = forms.CharField(widget=forms.PasswordInput)

class DecryptionForm(forms.Form):
    filename = forms.CharField(max_length=255)
    encryption_key = forms.CharField(widget=forms.PasswordInput)

class FriendFileShareForm(forms.Form):
    user = forms.ModelChoiceField(queryset=None, label="Share with friend")
    
    def __init__(self, *args, current_user=None, **kwargs):
        super().__init__(*args, **kwargs)
        if current_user:
            # Get friends of the current user (both directions)
            friends = User.objects.filter(
                Q(related_to__user=current_user, related_to__accepted=True) |
                Q(relations__related_user=current_user, relations__accepted=True)
            ).distinct()
            
            self.fields['user'].queryset = friends.exclude(id=current_user.id)  # Exclude current user from the list
