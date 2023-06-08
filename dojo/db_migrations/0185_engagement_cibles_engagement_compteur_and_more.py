# Generated by Django 4.1.7 on 2023-05-30 09:34

from django.db import migrations, models
import dojo.models


class Migration(migrations.Migration):

    dependencies = [
        ('dojo', '0184_engagement_cibles_engagement_compteur_and_more'),
    ]

    operations = [
       
        migrations.AddField(
            model_name='engagement',
            name='compteur',
            field=models.CharField(blank=True, default='', max_length=200),
        ),
        migrations.AddField(
            model_name='engagement',
            name='consequences',
            field=models.TextField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='engagement',
            name='mesures_impactees',
            field=models.TextField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='engagement',
            name='niveau_securite_global',
            field=models.TextField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='engagement',
            name='password',
            field=models.CharField(blank=True, max_length=150, null=True),
        ),
        migrations.AddField(
            model_name='engagement',
            name='risques',
            field=models.TextField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='finding',
            name='complexite',
            field=models.CharField(blank=True, help_text='complexite', max_length=511, null=True, verbose_name='complexite'),
        ),
        migrations.AddField(
            model_name='finding',
            name='priorite',
            field=models.CharField(blank=True, help_text='priorite', max_length=511, null=True, verbose_name='priorite'),
        ),
        migrations.AddField(
            model_name='finding',
            name='scenarioDeRisque',
            field=models.FileField(blank=True, null=True, upload_to=dojo.models.UniqueUploadNameProvider('uploaded_files')),
        ),
        migrations.AddField(
            model_name='finding',
            name='statut',
            field=models.CharField(default='Résolue', help_text='statut', max_length=511, verbose_name='statut'),
            preserve_default=False,
        ),
    ]
