# Generated by Django 3.1.13 on 2021-07-10 00:04

from django.conf import settings
from django.db import migrations, models, IntegrityError, transaction
import uuid
import django.db.models.deletion
import logging

logger = logging.getLogger(__name__)


def move_images_to_files(apps, schema_editor):
    Finding_model = apps.get_model('dojo', 'Finding')
    FileUpload_model = apps.get_model('dojo', 'FileUpload')
    for finding in Finding_model.objects.filter(images__isnull=False):
        passed = False
        for image in finding.images.all():
            caption_uuid = uuid.uuid4().hex
            try:
                with transaction.atomic():
                    file = FileUpload_model.objects.create(
                        title=image.caption if len(image.caption) and image.caption != '' else caption_uuid,
                        file=image.image
                    )
            except IntegrityError:
                logger.info('retrying migrate migration for image %s with caption %s by uuid', image.image.name, image.caption)
                try:
                    with transaction.atomic():
                        file = FileUpload_model.objects.create(
                            title=image.caption[:50] + '-' + caption_uuid,
                            file=image.image
                        )
                except IntegrityError:
                    passed = True
                    pass

            if not passed:
                finding.files.add(file)
            else:
                logger.warning('unable to migrate image %s with caption %s', image.image.name, image.caption)


class Migration(migrations.Migration):

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ('dojo', '0117_usercontactinfo_force_password_reset'),
    ]

    operations = [
        migrations.RunPython(move_images_to_files),
        migrations.CreateModel(
            name='FileAccessToken',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('token', models.CharField(max_length=255)),
                ('size', models.CharField(choices=[('small', 'Small'), ('medium', 'Medium'), ('large', 'Large'), ('thumbnail', 'Thumbnail'), ('original', 'Original')], default='medium', max_length=9)),
                ('file', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='dojo.fileupload')),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
        ),
        migrations.RemoveField(
            model_name='findingimageaccesstoken',
            name='image',
        ),
        migrations.RemoveField(
            model_name='findingimageaccesstoken',
            name='user',
        ),
        migrations.RemoveField(
            model_name='finding',
            name='images',
        ),
        migrations.DeleteModel(
            name='FindingImage',
        ),
        migrations.DeleteModel(
            name='FindingImageAccessToken',
        ),
    ]
