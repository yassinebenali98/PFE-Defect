# Generated by Django 4.1.7 on 2023-05-04 16:52

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('dojo', '0190_alter_finding_senario'),
    ]

    operations = [
        migrations.AlterField(
            model_name='finding',
            name='senario',
            field=models.OneToOneField(blank=True, help_text='Files(s) related to the flaw.', null=True, on_delete=django.db.models.deletion.CASCADE, related_name='senario_files', to='dojo.fileupload', verbose_name='Files'),
        ),
    ]
