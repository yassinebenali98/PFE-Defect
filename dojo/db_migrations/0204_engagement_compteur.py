# Generated by Django 4.1.7 on 2023-05-16 10:26

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('dojo', '0203_engagement_consequences_engagement_mesures_impactees_and_more'),
    ]

    operations = [
        migrations.AddField(
            model_name='engagement',
            name='compteur',
            field=models.JSONField(choices=[('generic', 'générique'), ('technique', 'technique'), ('organisationnelle', 'organisationnelle'), ('configuration', 'configuration')], default=list),
        ),
    ]
