# Generated by Django 4.1.7 on 2023-05-16 10:36

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('dojo', '0205_remove_engagement_description'),
    ]

    operations = [
        migrations.AddField(
            model_name='engagement',
            name='description',
            field=models.TextField(blank=True, null=True),
        ),
    ]