# Generated by Django 3.1.13 on 2021-10-27 07:01

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('dojo', '0132_remove_configs_from_test'),
    ]

    operations = [
        migrations.AddField(
            model_name='finding',
            name='service',
            field=models.CharField(blank=True, help_text='A service is a self-contained piece of functionality within a Product. This is an optional field which is used in deduplication of findings when set.', max_length=200, null=True, verbose_name='Service'),
        ),

        # These 3 fields contain auto-generated attributes of findings so they need the new service field as well
        migrations.AlterField(
            model_name='child_rule',
            name='match_field',
            field=models.CharField(choices=[('id', 'id'), ('title', 'title'), ('date', 'date'), ('sla_start_date', 'sla_start_date'), ('cwe', 'cwe'), ('cve', 'cve'), ('cvssv3', 'cvssv3'), ('cvssv3_score', 'cvssv3_score'), ('url', 'url'), ('severity', 'severity'), ('description', 'description'), ('mitigation', 'mitigation'), ('impact', 'impact'), ('steps_to_reproduce', 'steps_to_reproduce'), ('severity_justification', 'severity_justification'), ('references', 'references'), ('test', 'test'), ('active', 'active'), ('verified', 'verified'), ('false_p', 'false_p'), ('duplicate', 'duplicate'), ('duplicate_finding', 'duplicate_finding'), ('out_of_scope', 'out_of_scope'), ('risk_accepted', 'risk_accepted'), ('under_review', 'under_review'), ('review_requested_by', 'review_requested_by'), ('under_defect_review', 'under_defect_review'), ('defect_review_requested_by', 'defect_review_requested_by'), ('is_mitigated', 'is_mitigated'), ('thread_id', 'thread_id'), ('mitigated', 'mitigated'), ('mitigated_by', 'mitigated_by'), ('reporter', 'reporter'), ('numerical_severity', 'numerical_severity'), ('last_reviewed', 'last_reviewed'), ('last_reviewed_by', 'last_reviewed_by'), ('param', 'param'), ('payload', 'payload'), ('hash_code', 'hash_code'), ('line', 'line'), ('file_path', 'file_path'), ('component_name', 'component_name'), ('component_version', 'component_version'), ('static_finding', 'static_finding'), ('dynamic_finding', 'dynamic_finding'), ('created', 'created'), ('scanner_confidence', 'scanner_confidence'), ('sonarqube_issue', 'sonarqube_issue'), ('unique_id_from_tool', 'unique_id_from_tool'), ('vuln_id_from_tool', 'vuln_id_from_tool'), ('sast_source_object', 'sast_source_object'), ('sast_sink_object', 'sast_sink_object'), ('sast_source_line', 'sast_source_line'), ('sast_source_file_path', 'sast_source_file_path'), ('nb_occurences', 'nb_occurences'), ('publish_date', 'publish_date'), ('service', 'service')], max_length=200),
        ),
        migrations.AlterField(
            model_name='rule',
            name='applied_field',
            field=models.CharField(choices=[('id', 'id'), ('title', 'title'), ('date', 'date'), ('sla_start_date', 'sla_start_date'), ('cwe', 'cwe'), ('cve', 'cve'), ('cvssv3', 'cvssv3'), ('cvssv3_score', 'cvssv3_score'), ('url', 'url'), ('severity', 'severity'), ('description', 'description'), ('mitigation', 'mitigation'), ('impact', 'impact'), ('steps_to_reproduce', 'steps_to_reproduce'), ('severity_justification', 'severity_justification'), ('references', 'references'), ('test', 'test'), ('active', 'active'), ('verified', 'verified'), ('false_p', 'false_p'), ('duplicate', 'duplicate'), ('duplicate_finding', 'duplicate_finding'), ('out_of_scope', 'out_of_scope'), ('risk_accepted', 'risk_accepted'), ('under_review', 'under_review'), ('review_requested_by', 'review_requested_by'), ('under_defect_review', 'under_defect_review'), ('defect_review_requested_by', 'defect_review_requested_by'), ('is_mitigated', 'is_mitigated'), ('thread_id', 'thread_id'), ('mitigated', 'mitigated'), ('mitigated_by', 'mitigated_by'), ('reporter', 'reporter'), ('numerical_severity', 'numerical_severity'), ('last_reviewed', 'last_reviewed'), ('last_reviewed_by', 'last_reviewed_by'), ('param', 'param'), ('payload', 'payload'), ('hash_code', 'hash_code'), ('line', 'line'), ('file_path', 'file_path'), ('component_name', 'component_name'), ('component_version', 'component_version'), ('static_finding', 'static_finding'), ('dynamic_finding', 'dynamic_finding'), ('created', 'created'), ('scanner_confidence', 'scanner_confidence'), ('sonarqube_issue', 'sonarqube_issue'), ('unique_id_from_tool', 'unique_id_from_tool'), ('vuln_id_from_tool', 'vuln_id_from_tool'), ('sast_source_object', 'sast_source_object'), ('sast_sink_object', 'sast_sink_object'), ('sast_source_line', 'sast_source_line'), ('sast_source_file_path', 'sast_source_file_path'), ('nb_occurences', 'nb_occurences'), ('publish_date', 'publish_date'), ('service', 'service')], max_length=200),
        ),
        migrations.AlterField(
            model_name='rule',
            name='match_field',
            field=models.CharField(choices=[('id', 'id'), ('title', 'title'), ('date', 'date'), ('sla_start_date', 'sla_start_date'), ('cwe', 'cwe'), ('cve', 'cve'), ('cvssv3', 'cvssv3'), ('cvssv3_score', 'cvssv3_score'), ('url', 'url'), ('severity', 'severity'), ('description', 'description'), ('mitigation', 'mitigation'), ('impact', 'impact'), ('steps_to_reproduce', 'steps_to_reproduce'), ('severity_justification', 'severity_justification'), ('references', 'references'), ('test', 'test'), ('active', 'active'), ('verified', 'verified'), ('false_p', 'false_p'), ('duplicate', 'duplicate'), ('duplicate_finding', 'duplicate_finding'), ('out_of_scope', 'out_of_scope'), ('risk_accepted', 'risk_accepted'), ('under_review', 'under_review'), ('review_requested_by', 'review_requested_by'), ('under_defect_review', 'under_defect_review'), ('defect_review_requested_by', 'defect_review_requested_by'), ('is_mitigated', 'is_mitigated'), ('thread_id', 'thread_id'), ('mitigated', 'mitigated'), ('mitigated_by', 'mitigated_by'), ('reporter', 'reporter'), ('numerical_severity', 'numerical_severity'), ('last_reviewed', 'last_reviewed'), ('last_reviewed_by', 'last_reviewed_by'), ('param', 'param'), ('payload', 'payload'), ('hash_code', 'hash_code'), ('line', 'line'), ('file_path', 'file_path'), ('component_name', 'component_name'), ('component_version', 'component_version'), ('static_finding', 'static_finding'), ('dynamic_finding', 'dynamic_finding'), ('created', 'created'), ('scanner_confidence', 'scanner_confidence'), ('sonarqube_issue', 'sonarqube_issue'), ('unique_id_from_tool', 'unique_id_from_tool'), ('vuln_id_from_tool', 'vuln_id_from_tool'), ('sast_source_object', 'sast_source_object'), ('sast_sink_object', 'sast_sink_object'), ('sast_source_line', 'sast_source_line'), ('sast_source_file_path', 'sast_source_file_path'), ('nb_occurences', 'nb_occurences'), ('publish_date', 'publish_date'), ('service', 'service')], max_length=200),
        ),
    ]
