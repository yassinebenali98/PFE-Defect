# Generated by Django 4.1.7 on 2023-05-09 13:39

from django.db import migrations, models
import dojo.models


class Migration(migrations.Migration):

    dependencies = [
        ('dojo', '0201_alter_findingimage_image'),
    ]

    operations = [
        migrations.AlterField(
            model_name='findingimage',
            name='image',
            field=models.FileField(blank=True, null=True, upload_to=dojo.models.UniqueUploadNameProvider('uploaded_files')),
        ),
    ]
