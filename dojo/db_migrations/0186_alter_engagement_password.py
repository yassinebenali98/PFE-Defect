# Generated by Django 4.1.7 on 2023-05-30 16:06

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('dojo', '0185_engagement_cibles_engagement_compteur_and_more'),
    ]

    operations = [
        migrations.AlterField(
            model_name='engagement',
            name='password',
            field=models.TextField(blank=True, null=True),
        ),
    ]
