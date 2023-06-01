# Generated by Django 3.2.13 on 2022-05-28 20:06
import logging

from django.db import migrations, models

logger = logging.getLogger(__name__)


# def save_existing_sla(apps, schema_editor):
#     system_settings_model = apps.get_model('dojo', 'System_Settings')
#
#     try:
#         system_settings = system_settings_model.objects.get()
#         critical = system_settings.sla_critical,
#         high = system_settings.sla_high,
#         medium = system_settings.sla_medium,
#         low = system_settings.sla_low
#     except:
#         critical = 7
#         high = 30
#         medium = 90
#         low = 120
#
#     SLA_Configuration = apps.get_model('dojo', 'SLA_Configuration')
#     SLA_Configuration.objects.create(name='Default',
#                                      description='The Default SLA Configuration. Products not using an explicit SLA Configuration will use this one.',
#                                      critical=critical,
#                                      high=high,
#                                      medium=medium,
#                                      low=low)


class Migration(migrations.Migration):
    dependencies = [
        ('dojo', '0164_remove_system_settings_staff_user_email_pattern'),
    ]

    operations = [
        migrations.CreateModel(
            name='SLA_Configuration',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(help_text='A unique name for the set of SLAs.', max_length=128, unique=True,
                                          verbose_name='Custom SLA Name')),
                ('description', models.CharField(blank=True, max_length=512, null=True)),
                ('critical', models.IntegerField(default=7, help_text='number of days to remediate a critical finding.',
                                                 verbose_name='Critical Finding SLA Days')),
                ('high', models.IntegerField(default=30, help_text='number of days to remediate a high finding.',
                                             verbose_name='High Finding SLA Days')),
                ('medium', models.IntegerField(default=90, help_text='number of days to remediate a medium finding.',
                                               verbose_name='Medium Finding SLA Days')),
                ('low', models.IntegerField(default=120, help_text='number of days to remediate a low finding.',
                                            verbose_name='Low Finding SLA Days')),
            ],
            options={
                'ordering': ['name'],
            },
        )
    ]
