from django import template
from dojo.models import Engagement
from dojo.reports.widgets import priority_pie_chart

register = template.Library()

@register.simple_tag
def engagement_priority_pie_chart(engagement_id):
    try:
        engagement = Engagement.objects.get(id=engagement_id)
        findings = engagement.findings.all()
        chart_html = priority_pie_chart(findings)
        return chart_html
    except Engagement.DoesNotExist:
        return ''
