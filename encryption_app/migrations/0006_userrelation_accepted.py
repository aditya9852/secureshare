# Generated by Django 5.1.2 on 2024-12-03 15:22

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('encryption_app', '0005_userrelation'),
    ]

    operations = [
        migrations.AddField(
            model_name='userrelation',
            name='accepted',
            field=models.BooleanField(default=False),
        ),
    ]
