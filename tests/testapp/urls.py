from django.urls import path

from . import views

urlpatterns = [
    path(
        "test_no_restrictions/", views.test_no_restrictions, name="test-no-restrictions"
    ),
    path("test_quicksand/", views.test_quicksand, name="test-quicksand"),
    path(
        "test_file_size_limit/", views.test_file_size_limit, name="test-file-size-limit"
    ),
    path(
        "test_filename_length_limit/",
        views.test_filename_length_limit,
        name="test-filename-length-limit",
    ),
    path(
        "test_whitelist_custom/",
        views.test_whitelist_custom,
        name="test-whitelist-custom",
    ),
    path("test_sanitization/", views.test_sanitization, name="test-sanitization"),
    path("test_clamav/", views.test_clamav, name="test-clamav"),
    path("test_yara/", views.test_yara, name="test-yara"),
]
