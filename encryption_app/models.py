from django.db import models
from django.contrib.auth.models import User

class EncryptedFile(models.Model):
    filename = models.CharField(max_length=255)
    file_extension = models.CharField(max_length=20)
    file_bytes = models.BinaryField()
    uploaded_at = models.DateTimeField(auto_now_add=True)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='encrypted_files')
    shared_with = models.ManyToManyField(User, through='FileShare', related_name='shared_files')

    def __str__(self):
        return self.filename

class UserRelation(models.Model):
    user = models.ForeignKey(User, related_name='user_relations_encryption_app', on_delete=models.CASCADE)
    friend = models.ForeignKey(User, related_name='friend_relations_encryption_app', on_delete=models.CASCADE)
    relationship_type = models.CharField(max_length=50)
    created_at = models.DateTimeField(auto_now_add=True)
    
    def __str__(self):
        return f"{self.user} - {self.friend} ({self.relationship_type})"

class FileShare(models.Model):
    file = models.ForeignKey(EncryptedFile, on_delete=models.CASCADE)
    shared_with = models.ForeignKey(User, on_delete=models.CASCADE)
    shared_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ('file', 'shared_with')

    def __str__(self):
        return f"{self.file.filename} shared with {self.shared_with.username}"
