# Generated by Django 3.2.15 on 2022-08-29 12:01

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('dojo', '0169_planned_remediation_date'),
    ]

    operations = [
        migrations.AddField(
            model_name='jira_project',
            name='custom_fields',
            field=models.JSONField(blank=True, help_text='JIRA custom field JSON mapping of Id to value, e.g. {"customfield_10122": [{"name": "8.0.1"}]}', max_length=200, null=True),
        ),
    ]
