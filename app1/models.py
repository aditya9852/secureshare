from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone


class UserRelation(models.Model):
    user = models.ForeignKey(User, related_name='user_relations_app1', on_delete=models.CASCADE)
    friend = models.ForeignKey(User, related_name='friend_relations_app1', on_delete=models.CASCADE)
    accepted = models.BooleanField(default=False)  # Whether the friendship has been accepted or not
    accepted = models.BooleanField(default=False)
    def __str__(self):
        return f"{self.user.username} - {self.friend.username}"


class Messages(models.Model):
    description = models.TextField()
    sender_name = models.ForeignKey(
        User, on_delete=models.CASCADE, related_name="sender"
    )
    receiver_name = models.ForeignKey(
        User, on_delete=models.CASCADE, related_name="receiver"
    )
    time = models.TimeField(auto_now_add=True)
    seen = models.BooleanField(default=False)
    timestamp = models.DateTimeField(default=timezone.now, blank=True)

    class Meta:
        ordering = ("timestamp",)
