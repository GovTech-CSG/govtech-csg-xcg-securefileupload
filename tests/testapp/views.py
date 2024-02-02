from django.http import HttpResponse, HttpResponseForbidden
from django.shortcuts import render
from django.urls import reverse

from govtech_csg_xcg.securefileupload.decorator import upload_config

from .forms import TestForm


def process_form(request, view_name):
    if request.method == "POST":
        form = TestForm(request.POST, request.FILES)
        if form.is_valid():
            return HttpResponse(request.FILES["uploaded_file"].name)
        else:
            return HttpResponseForbidden("Upload not allowed")
    else:
        form = TestForm()

    return render(
        request, "test_form.html", {"form": form, "view_path": reverse(view_name)}
    )


def test_no_restrictions(request):
    return process_form(request, "test-no-restrictions")


@upload_config(quicksand=True)
def test_quicksand(request):
    return process_form(request, "test-quicksand")


@upload_config(file_size_limit=200)
def test_file_size_limit(request):
    return process_form(request, "test-file-size-limit")


@upload_config(filename_length_limit=50)
def test_filename_length_limit(request):
    return process_form(request, "test-filename-length-limit")


@upload_config(whitelist_name="CUSTOM", whitelist=["text/plain"])
def test_whitelist_custom(request):
    return process_form(request, "test-whitelist-custom")


# Config for sanitization=True has been performed in settings/default.py
# We test sanitization=True + keep_original_filename=True using settings/keep_filename.py
def test_sanitization(request):
    return process_form(request, "test-sanitization")


def test_clamav(request):
    return process_form(request, "test-clamav")


def test_yara(request):
    return process_form(request, "test-yara")
