from itertools import groupby
import logging
from operator import attrgetter
import os
from auditlog.models import LogEntry
from django.contrib.contenttypes.models import ContentType
from django.contrib import messages
from django.core.exceptions import PermissionDenied, ObjectDoesNotExist
from django.http import Http404, HttpResponseRedirect, FileResponse
from django.conf import settings
from django.urls import reverse
from django.contrib.auth.decorators import login_required
from django.views.static import serve
from django.shortcuts import render, get_object_or_404
from dojo.models import Engagement, Test, Finding, Endpoint, Product, FileUpload
from dojo.filters import LogEntryFilter
from dojo.forms import ManageFileFormSet
from dojo.utils import get_page_items, Product_Tab, get_system_setting
from dojo.authorization.authorization import user_has_permission, user_has_permission_or_403, user_has_configuration_permission_or_403
from dojo.authorization.roles_permissions import Permissions
from django.shortcuts import render
from django.http import HttpResponse
from weasyprint import HTML
from django.template.loader import get_template
from xhtml2pdf import pisa
from django.contrib.staticfiles import finders
from django.conf import settings
from django.core.exceptions import SuspiciousFileOperation
from django.templatetags.static import static
import matplotlib.pyplot as plt
from django.db.models import Count
from chartjs.views.lines import BaseLineChartView
from django.views.generic import TemplateView

from dojo.filters import ReportFindingFilter

from collections import Counter
import json
from io import BytesIO
import base64
import tempfile







logger = logging.getLogger(__name__)
def link_callback(uri, rel):
    """
    Convert HTML URIs to absolute system paths so xhtml2pdf can access those
    resources
    """
    # use Django's static file handling
    sUrl = static(settings.STATIC_URL)
    mUrl = static(settings.MEDIA_URL)

    if uri.startswith(mUrl):
        path = os.path.join(settings.MEDIA_ROOT, uri.replace(mUrl, ""))
    elif uri.startswith(sUrl):
        path = os.path.join(settings.STATIC_ROOT, uri.replace(sUrl, ""))
    else:
        return uri

    # make sure that file exists
    if not os.path.isfile(path):
        raise Exception(
            'media URI must start with %s or %s' % (sUrl, mUrl)
        )
    return path
import base64
from django.core.files.storage import default_storage

def priority_pie_chart(request,engagement_id):
    engagement = Engagement.objects.get(id=engagement_id)
    findings = Finding.objects.filter(test__engagement=engagement)
    priorities = findings.values_list('priorite', flat=True)
    count = Counter(priorities)

    # Convert dictionary to JSON
    priorities_json = json.dumps(dict(count))

    return render(request, 'dojo/priority_pie_chart.html', {'priorities': priorities_json})

def image_to_data_uri(image_path):
    try:
        with default_storage.open(image_path, 'rb') as f:
            image_data = f.read()
            mime_type = mimetypes.guess_type(image_path)[0]
            encoded_data = base64.b64encode(image_data).decode('utf-8')
            return f'data:{mime_type};base64,{encoded_data}'
    except Exception as e:
        print(f"Error converting image to data URI: {e}")
        return None

from io import BytesIO
import base64
import tempfile
from collections import Counter
import json
import pygal
from pygal.style import Style
import base64
import cairosvg
import io
import xml.dom.minidom

def generate_pie_priorities_chart(findings):
    # Generate the chart data
    priorities = findings.values_list('priorite', flat=True)
    count = Counter(priorities)
    total_count = sum(count.values())

    # Define the color map
    color_map = {
        'Immédiate': '#C23B21',
        'Court Terme': '#FF8B01',
        'Moyenne Terme': '#FFD301',
        'Long Terme': '#00B050',
        'None': '#000000'
    }

    # Predefine the order of the priorities
    priority_order = ['Immédiate', 'Court Terme', 'Moyenne Terme', 'Long Terme']

    # Generate chart data in the desired order
    chart_data = [(priority, count[priority], count[priority] / total_count) for priority in priority_order if priority in count]

    # Create a new pie chart using pygal
    chart_style = Style(colors=[color_map[priority] for priority in priority_order])
    chart = pygal.Pie(style=chart_style)
    chart.title = 'Priority Pie Chart'
    chart.legend_at_bottom = True
    chart.print_values = True
    chart.human_readable = True

    for priority, count, percentage in chart_data:
        formatted_percentage = f'{percentage:.0%}'
        label = f"{priority} {formatted_percentage} ({count})"
        chart.add(label, count)

    return chart

def generate_pie_complexite_chart(findings):
    # Generate the chart data
    complexites = findings.values_list('complexite', flat=True)
    count = Counter(complexites)
    total_count = sum(count.values())

    # Define the color map
    color_map = {
        'Simple': '#C23B21',
        'Moyenne': '#FF8B01',
        'Complexe': '#FFD301'
    }

    # Predefine the order of the priorities
    complexite_order = ['Simple', 'Moyenne', 'Complexe']

    # Generate chart data in the desired order
    chart_data = [(complexite, count[complexite], count[complexite] / total_count) for complexite in complexite_order if complexite in count]

    # Create a new pie chart using pygal
    chart_style = Style(colors=[color_map[complexite] for complexite in complexite_order])
    chart = pygal.Pie(style=chart_style)
    chart.title = 'Complexite Pie Chart'
    chart.legend_at_bottom = True
    chart.print_values = True
    chart.human_readable = True

    for complexite, count, percentage in chart_data:
        formatted_percentage = f'{percentage:.0%}'
        label = f"{complexite} {formatted_percentage} ({count})"
        chart.add(label, count)

    return chart

def generate_pie_severities_chart(findings):
    # Generate the chart data
    severities = findings.values_list('severity', flat=True)
    count = Counter(severities)
    total_count = sum(count.values())

    # Define the color map
    color_map = {
        'Critical': '#C23B21',
        'High': '#FF8B01',
        'Medium': '#FFD301',
        'Low': '#00B050',
    }

    # Predefine the order of the priorities
    severity_order = ['Critical', 'High', 'Medium','Low']

    # Generate chart data in the desired order
    chart_data = [(severity, count[severity], count[severity] / total_count) for severity in severity_order if severity in count]

    # Create a new pie chart using pygal
    chart_style = Style(colors=[color_map[severity] for severity in severity_order])
    chart = pygal.Pie(style=chart_style)
    chart.title = 'severity Pie Chart'
    chart.legend_at_bottom = True
    chart.print_values = True
    chart.human_readable = True

    for severity, count, percentage in chart_data:
        formatted_percentage = f'{percentage:.0%}'
        label = f"{severity} {formatted_percentage} ({count})"
        chart.add(label, count)

    return chart


def my_report_view(request, engagement_id):
    logger = logging.getLogger('weasyprint')
    logger.addHandler(logging.StreamHandler())
    logger.setLevel(logging.DEBUG)

    engagement = Engagement.objects.get(id=engagement_id)
    product = engagement.product
    findings = Finding.objects.filter(test__engagement=engagement)

    # Generate the chart
    chart = generate_pie_priorities_chart(findings)
    # Save the chart as a PNG buffer
    png_buffer = chart.render_to_png()
    # Convert the PNG buffer to a base64-encoded string
    priorities_png_base64 = base64.b64encode(png_buffer).decode('utf-8')

    chart = generate_pie_complexite_chart(findings)
    png_buffer = chart.render_to_png()
    complexites_png_base64 = base64.b64encode(png_buffer).decode('utf-8')


    chart = generate_pie_severities_chart(findings)
    png_buffer = chart.render_to_png()
    severities_png_base64 = base64.b64encode(png_buffer).decode('utf-8')



    
    
    # Turn the filtered findings into a list and sort them by the 'name' field of 'test' and 'severity'
    findings_list = sorted(list(findings), key=attrgetter('test.title', 'severity'))
    

    # Group the sorted findings by the 'name' field of 'test' and 'severity'
    grouped_findings = {}
    for key, group in groupby(findings_list, key=attrgetter('test.title')):
        grouped_findings[key] = {k: list(v) for k, v in groupby(group, key=attrgetter('severity'))}


    # Render the HTML template with the chart image
    context = {'engagement': engagement, 'product': product, 'findings': findings, 'include_table_of_contents': 1, 'image_to_data_uri': image_to_data_uri,
                'priorities_chart_image': priorities_png_base64,'complexite_chart_image': complexites_png_base64,'severities_chart_image': severities_png_base64,
                  'grouped_findings':grouped_findings  }
    html_string = render(request, 'dojo/engagement_pdf_report.html', context).content.decode('utf-8')

    # Create a PDF file using WeasyPrint
    pdf_file = HTML(string=html_string).write_pdf()

    # Return the PDF file as an HTTP response
    response = HttpResponse(pdf_file, content_type='application/pdf')
    response['Content-Disposition'] = ''
    return response

def custom_error_view(request, exception=None):
    return render(request, "500.html", {})


def custom_bad_request_view(request, exception=None):
    return render(request, "400.html", {})


def action_history(request, cid, oid):
    try:
        ct = ContentType.objects.get_for_id(cid)
        obj = ct.get_object_for_this_type(pk=oid)
    except (KeyError, ObjectDoesNotExist):
        raise Http404()

    product_id = None
    active_tab = None
    finding = None
    test = False
    object_value = None

    if ct.model == "product":
        user_has_permission_or_403(request.user, obj, Permissions.Product_View)
        product_id = obj.id
        active_tab = "overview"
        object_value = Product.objects.get(id=obj.id)
    elif ct.model == "engagement":
        user_has_permission_or_403(request.user, obj, Permissions.Engagement_View)
        object_value = Engagement.objects.get(id=obj.id)
        product_id = object_value.product.id
        active_tab = "engagements"
    elif ct.model == "test":
        user_has_permission_or_403(request.user, obj, Permissions.Test_View)
        object_value = Test.objects.get(id=obj.id)
        product_id = object_value.engagement.product.id
        active_tab = "engagements"
        test = True
    elif ct.model == "finding":
        user_has_permission_or_403(request.user, obj, Permissions.Finding_View)
        object_value = Finding.objects.get(id=obj.id)
        product_id = object_value.test.engagement.product.id
        active_tab = "findings"
        finding = object_value
    elif ct.model == "endpoint":
        user_has_permission_or_403(request.user, obj, Permissions.Endpoint_View)
        object_value = Endpoint.objects.get(id=obj.id)
        product_id = object_value.product.id
        active_tab = "endpoints"
    elif ct.model == "risk_acceptance":
        engagements = Engagement.objects.filter(risk_acceptance=obj)
        authorized = False
        for engagement in engagements:
            if user_has_permission(request.user, engagement, Permissions.Engagement_View):
                authorized = True
                break
        if not authorized:
            raise PermissionDenied
    elif ct.model == "user":
        user_has_configuration_permission_or_403(request.user, 'auth.view_user')
    else:
        if not request.user.is_superuser:
            raise PermissionDenied

    product_tab = None
    if product_id:
        product_tab = Product_Tab(get_object_or_404(Product, id=product_id), title="History", tab=active_tab)
        if active_tab == "engagements":
            if str(ct) == "engagement":
                product_tab.setEngagement(object_value)
            else:
                product_tab.setEngagement(object_value.engagement)

    history = LogEntry.objects.filter(content_type=ct,
                                      object_pk=obj.id).order_by('-timestamp')
    log_entry_filter = LogEntryFilter(request.GET, queryset=history)
    paged_history = get_page_items(request, log_entry_filter.qs, 25)

    if not get_system_setting('enable_auditlog'):
        messages.add_message(
            request,
            messages.WARNING,
            'Audit logging is currently disabled in System Settings.',
            extra_tags='alert-danger')

    return render(request, 'dojo/action_history.html',
                  {"history": paged_history,
                   'product_tab': product_tab,
                   "filtered": history,
                   "log_entry_filter": log_entry_filter,
                   "obj": obj,
                   "test": test,
                   "object_value": object_value,
                   "finding": finding
                   })


def manage_files(request, oid, obj_type):
    if obj_type == 'Engagement':
        obj = get_object_or_404(Engagement, pk=oid)
        user_has_permission_or_403(request.user, obj, Permissions.Engagement_Edit)
        obj_vars = ('view_engagement', 'engagement_set')
    elif obj_type == 'Test':
        obj = get_object_or_404(Test, pk=oid)
        user_has_permission_or_403(request.user, obj, Permissions.Test_Edit)
        obj_vars = ('view_test', 'test_set')
    elif obj_type == 'Finding':
        obj = get_object_or_404(Finding, pk=oid)
        user_has_permission_or_403(request.user, obj, Permissions.Finding_Edit)
        obj_vars = ('view_finding', 'finding_set')
    else:
        raise Http404()

    files_formset = ManageFileFormSet(queryset=obj.files.all())
    error = False

    if request.method == 'POST':
        files_formset = ManageFileFormSet(
            request.POST, request.FILES, queryset=obj.files.all())
        if files_formset.is_valid():
            # remove all from database and disk

            files_formset.save()

            for o in files_formset.deleted_objects:
                logger.debug("removing file: %s", o.file.name)
                os.remove(os.path.join(settings.MEDIA_ROOT, o.file.name))

            for o in files_formset.new_objects:
                logger.debug("adding file: %s", o.file.name)
                obj.files.add(o)

            orphan_files = FileUpload.objects.filter(engagement__isnull=True,
                                                     test__isnull=True,
                                                     finding__isnull=True)
            for o in orphan_files:
                logger.debug("purging orphan file: %s", o.file.name)
                os.remove(os.path.join(settings.MEDIA_ROOT, o.file.name))
                o.delete()

            messages.add_message(
                request,
                messages.SUCCESS,
                'Files updated successfully.',
                extra_tags='alert-success')

        else:
            error = True
            messages.add_message(
                request,
                messages.ERROR,
                'Please check form data and try again.',
                extra_tags='alert-danger')

        if not error:
            return HttpResponseRedirect(reverse(obj_vars[0], args=(oid, )))
    return render(
        request, 'dojo/manage_files.html', {
            'files_formset': files_formset,
            'obj': obj,
            'obj_type': obj_type,
        })


# Serve the file only after verifying the user is supposed to see the file
@login_required
def protected_serve(request, path, document_root=None, show_indexes=False):
    try:
        file = FileUpload.objects.get(file=path)
    except FileUpload.DoesNotExist:
        # If the file is not found in the FileUpload model, you can serve the file directly.
        # Alternatively, you can apply your own custom logic here.
        return serve(request, path, document_root, show_indexes)
    file = FileUpload.objects.get(file=path)
    if not file:
        raise Http404()
    object_set = list(file.engagement_set.all()) + list(file.test_set.all()) + list(file.finding_set.all())
    # Should only one item (but not sure what type) in the list, so O(n=1)
    for obj in object_set:
        if isinstance(obj, Engagement):
            user_has_permission_or_403(request.user, obj, Permissions.Engagement_View)
        elif isinstance(obj, Test):
            user_has_permission_or_403(request.user, obj, Permissions.Test_View)
        elif isinstance(obj, Finding):
            user_has_permission_or_403(request.user, obj, Permissions.Finding_View)
    return serve(request, path, document_root, show_indexes)


def access_file(request, fid, oid, obj_type, url=False):
    if obj_type == 'Engagement':
        obj = get_object_or_404(Engagement, pk=oid)
        user_has_permission_or_403(request.user, obj, Permissions.Engagement_View)
    elif obj_type == 'Test':
        obj = get_object_or_404(Test, pk=oid)
        user_has_permission_or_403(request.user, obj, Permissions.Test_View)
    elif obj_type == 'Finding':
        obj = get_object_or_404(Finding, pk=oid)
        user_has_permission_or_403(request.user, obj, Permissions.Finding_View)
    else:
        raise Http404()
    # If reaching this far, user must have permission to get file
    file = get_object_or_404(FileUpload, pk=fid)
    redirect_url = '{media_root}/{file_name}'.format(
        media_root=settings.MEDIA_ROOT,
        file_name=file.file.url.lstrip(settings.MEDIA_URL))
    print(redirect_url)
    return FileResponse(open(redirect_url))
