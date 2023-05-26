import datetime
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
from weasyprint import HTML, CSS, Document
from weasyprint.text.fonts import FontConfiguration
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
import hashlib
from PyPDF2 import PdfReader, PdfWriter



from dojo.filters import ReportFindingFilter

from collections import Counter
import json
from io import BytesIO
import base64
import tempfile

from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, PageTemplate, BaseDocTemplate, Frame, Paragraph
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import inch







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

    # Create a new pie chart using matplotlib
    labels = []
    sizes = []
    colors = []

    for priority, count, percentage in chart_data:
        formatted_percentage = f'{int(percentage * 100)}%'
        label = f"{priority} {formatted_percentage}"
        labels.append(label)
        sizes.append(count)
        colors.append(color_map[priority])

    fig, ax = plt.subplots()
    ax.pie(sizes, labels=labels, colors=colors, autopct='%1.0f%%')
    ax.set_title('')

    ax.set_xlabel('PRIORITE DE MISE EN OEUVRE', loc='center', fontsize=16)
    # Convert the chart image to a base64-encoded string
    chart_image = io.BytesIO()
    plt.savefig(chart_image, format='png')
    chart_image.seek(0)
    chart_base64 = base64.b64encode(chart_image.read()).decode('utf-8')

    plt.close()

    return chart_base64

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

    # Predefine the order of the complexites
    complexite_order = ['Simple', 'Moyenne', 'Complexe']

    # Generate chart data in the desired order
    chart_data = [(complexite, count[complexite], count[complexite] / total_count) for complexite in complexite_order if complexite in count]

    # Create a new pie chart using matplotlib
    labels = []
    sizes = []
    colors = []

    for complexite, count, percentage in chart_data:
        formatted_percentage = f'{int(percentage * 100)}%'
        label = f"{complexite} {formatted_percentage}"
        labels.append(label)
        sizes.append(count)
        colors.append(color_map[complexite])

    fig, ax = plt.subplots()
    ax.pie(sizes, labels=labels, colors=colors, autopct='%1.0f%%')
    ax.set_title('')
    ax.set_xlabel('COMPLEXITE DE MISE EN OEUVRE', loc='center', fontsize=16)

    # Convert the chart image to a base64-encoded string
    chart_image = io.BytesIO()
    plt.savefig(chart_image, format='png')
    chart_image.seek(0)
    chart_base64 = base64.b64encode(chart_image.read()).decode('utf-8')

    plt.close()

    return chart_base64


def generate_pie_severities_chart(findings):
    # Generate the chart data
    severities = findings.values_list('severity', flat=True)
    count = Counter(severities)
    total_count = sum(count.values())

    # Define the display labels for each severity level
    display_labels = {
        'Critical': 'Critique',
        'High': 'Forte',
        'Medium': 'Moyenne',
        'Low': 'Faible',
        'Info': 'Générique',
    }

    # Define the color map
    color_map = {
        'Critical': '#C23B21',
        'High': '#FF8B01',
        'Medium': '#FFD301',
        'Low': '#00B050',
        'Info': '#999999',
    }

    # Predefine the order of the severities
    severity_order = ['Critical', 'High', 'Medium', 'Low', 'Info']

    # Generate chart data in the desired order
    chart_data = [(severity, count[severity], count[severity] / total_count) for severity in severity_order if severity in count]

    # Create a new pie chart using matplotlib
    labels = []
    sizes = []
    colors = []

    for severity, count, percentage in chart_data:
        formatted_percentage = f'{int(percentage * 100)}%'
        display_label = f"{display_labels[severity]} {formatted_percentage}"
        labels.append(display_label)
        sizes.append(count)
        colors.append(color_map[severity])

    fig, ax = plt.subplots()
    ax.pie(sizes, labels=labels, colors=colors, autopct='%1.0f%%')
    ax.set_title('')
    ax.set_xlabel('STATISTIQUES SUR LES VULNÉRABILITÉS', loc='center', fontsize=16)
    # Convert the chart image to a base64-encoded string
    chart_image = io.BytesIO()
    plt.savefig(chart_image, format='png')
    chart_image.seek(0)
    chart_base64 = base64.b64encode(chart_image.read()).decode('utf-8')

    plt.close()

    return chart_base64

class CustomPageTemplate(PageTemplate):
    def __init__(self, id):
        frames = [
            Frame(30, 30, 550, 800, id='normal', showBoundary=0),
            Frame(30, 15, 550, 800, id='footer', showBoundary=0),
        ]
        PageTemplate.__init__(self, id, frames=frames)

    def afterDrawPage(self, canvas, doc):
        canvas.saveState()
        canvas.setFont('Helvetica', 10)
        canvas.drawString(40, 20, f"Page {doc.page}")
        canvas.restoreState()

from django.contrib.auth.hashers import make_password, check_password
        

def my_report_view(request, engagement_id):
    logger = logging.getLogger('weasyprint')
    logger.addHandler(logging.StreamHandler())
    logger.setLevel(logging.DEBUG)
   
    tests = Test.objects.none()

    engagement = Engagement.objects.get(id=engagement_id)
    product = engagement.product
    findings = Finding.objects.filter(test__engagement=engagement)
    
    # Generate the chart images
    priorities_png_base64 = generate_pie_priorities_chart(findings)
    complexite_png_base64 = generate_pie_complexite_chart(findings)
    severities_png_base64 = generate_pie_severities_chart(findings)

    # Count the findings
    counts = {
        'Technique': findings.filter(type='Technique').count(),
        'Organisationnelle': findings.filter(type='Organisationnelle').count(),
        'Confuguration': findings.filter(type='Confuguration').count()
    }
    counts['generic'] = findings.filter(severity='Info').count()

    # Sort and group the findings
    findings_list = sorted(list(findings), key=attrgetter('test.title', 'severity'))
    grouped_findings = {}
    for key, group in groupby(findings_list, key=attrgetter('test.title')):
            avances_findings = []
            generiques_findings = []

            for finding in group:
                if finding.severity != 'Info':
                    avances_findings.append(finding)
                elif finding.severity == 'Info':
                    generiques_findings.append(finding)

            grouped_findings[key] = {
                'avances': avances_findings,
                'generiques': generiques_findings
            }

    tests = tests
    advanced_threats_findings = []
    generic_findings = []

    # Iterate over all the findings
    for finding in findings:
        if finding.severity != 'Info':
            # Check if the finding belongs to advanced threats based on severity
            advanced_threats_findings.append(finding)
        else:
            # Check if the finding belongs to generic findings based on severity
            generic_findings.append(finding)

    # Render the HTML template with the chart images and findings
    context = {
        'engagement': engagement,
        'product': product,
        'tests': tests,
        'advanced_threats_findings': advanced_threats_findings,
        'generic_findings': generic_findings,
        'findings': findings,  # Include the findings queryset
        'include_table_of_contents': 1,
        'priorities_chart_image': priorities_png_base64,
        'complexite_chart_image': complexite_png_base64,
        'severities_chart_image': severities_png_base64,
        'grouped_findings': grouped_findings,
        'counts': counts
    }
    html_string = render(request, 'dojo/engagement_pdf_report.html', context).content.decode('utf-8')

    # Create a CSS string for the footer
    footer_css = '''
    @page {
        @bottom-left {
            content: "© TALAN – 2022";
            font-size: 10pt;
            
        }
        @bottom-center {
            content: "www.talan.com";
            font-size: 10pt;
            
        }
        @bottom-right {
            content: "Page " counter(page) "/" counter(pages);
            font-size: 10pt;
        }
    }
    '''

    # Create a PDF document using WeasyPrint and apply the CSS for the footer
    font_config = FontConfiguration()
    document = HTML(string=html_string).render(stylesheets=[CSS(string=footer_css)], font_config=font_config)

    # Set the file name with the current date
    current_date = datetime.datetime.now().strftime('%d%m%y')
    file_name = f'{current_date}-Rapport de pentest {product.name} {engagement.name}.pdf'

    # Create a byte string for the PDF content
    pdf_bytes = document.write_pdf()

    # Encrypt the PDF file with the original password
    encrypted_pdf_bytes = encrypt_pdf(pdf_bytes, engagement.get_decrypted_password(), engagement.get_decrypted_password())

    # Return the encrypted PDF file as an HTTP response with the updated file name
    response = HttpResponse(encrypted_pdf_bytes, content_type='application/pdf')
    response['Content-Disposition'] = f'attachment; filename="{file_name}"'
    return response


def encrypt_pdf(pdf_bytes, owner_password, user_password):
    pdf_reader = PdfReader(io.BytesIO(pdf_bytes))
    pdf_writer = PdfWriter()

    for page in pdf_reader.pages:
        pdf_writer.add_page(page)

    pdf_writer.encrypt(user_pwd=user_password, owner_pwd=owner_password)

    output_stream = io.BytesIO()
    pdf_writer.write(output_stream)
    encrypted_pdf_bytes = output_stream.getvalue()

    return encrypted_pdf_bytes


def chart_to_base64(chart):
    png_buffer = chart.render_to_png()
    png_base64 = base64.b64encode(png_buffer).decode('utf-8')
    return png_base64
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
