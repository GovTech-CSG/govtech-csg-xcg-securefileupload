import logging
import os
import re
import unittest

from django.conf import settings
from django.test import SimpleTestCase
from django.urls import reverse
from parameterized import parameterized

logging.getLogger("securefileupload").setLevel(logging.ERROR)
SETTINGS_MODULE_NAME = os.getenv("DJANGO_SETTINGS_MODULE")


@unittest.skipUnless(SETTINGS_MODULE_NAME == "testproject.settings.default", "")
class TestSecureFileUploadFeatures(SimpleTestCase):
    """Unit tests for the various features of the Secure File Upload middleware."""

    @parameterized.expand(
        [
            ("control.txt",),
            ("malicious_file_eicar.com.txt",),
            ("overly_large_file.jpg",),
            (
                "long_file_name_cxuUUGz166w44LA0neLP3QtYQeF5tgeJuawFCSJYNNAIVxp3mjnoZOFuLibg4u5R.txt",
            ),
            ("legit_pdf_file.pdf",),
            # We don't include pdf_file_with_extension_changed.txt because securefileupload will reject files with manipulated extensions even if all other features are turned off.
        ]
    )
    def test_all_payloads_allowed_when_no_restrictions(self, filename):
        filepath = settings.BASE_DIR / f"testapp/test_files/{filename}"
        with open(filepath, "rb") as file:
            response = self.client.post(
                reverse("test-no-restrictions"), {"uploaded_file": file}
            )
        self.assertEqual(response.status_code, 200)

    @parameterized.expand(
        [
            ("control.txt", 200),
            ("malicious_file_eicar.com.txt", 403),
        ]
    )
    def test_quicksand_detects_malicious_file(self, filename, status_code):
        filepath = settings.BASE_DIR / f"testapp/test_files/{filename}"
        with open(filepath, "rb") as file:
            response = self.client.post(
                reverse("test-quicksand"), {"uploaded_file": file}
            )
        self.assertEqual(response.status_code, status_code)

    @parameterized.expand(
        [
            ("control.txt", 200),
            ("overly_large_file.jpg", 403),
        ]
    )
    def test_file_size_limit_rejects_overly_large_file(self, filename, status_code):
        filepath = settings.BASE_DIR / f"testapp/test_files/{filename}"
        with open(filepath, "rb") as file:
            response = self.client.post(
                reverse("test-file-size-limit"), {"uploaded_file": file}
            )
        self.assertEqual(response.status_code, status_code)

    @parameterized.expand(
        [
            ("control.txt", 200),
            (
                "long_file_name_cxuUUGz166w44LA0neLP3QtYQeF5tgeJuawFCSJYNNAIVxp3mjnoZOFuLibg4u5R.txt",
                403,
            ),
        ]
    )
    def test_filename_length_limit_rejects_long_names(self, filename, status_code):
        filepath = settings.BASE_DIR / f"testapp/test_files/{filename}"
        with open(filepath, "rb") as file:
            response = self.client.post(
                reverse("test-filename-length-limit"), {"uploaded_file": file}
            )
        self.assertEqual(response.status_code, status_code)

    @parameterized.expand(
        [
            ("control.txt", 200),
            ("legit_pdf_file.pdf", 403),
            ("pdf_file_with_extension_changed.txt", 403),
        ]
    )
    def test_whitelist_only_accepts_whitelisted_file_types(self, filename, status_code):
        filepath = settings.BASE_DIR / f"testapp/test_files/{filename}"
        with open(filepath, "rb") as file:
            response = self.client.post(
                reverse("test-whitelist-custom"), {"uploaded_file": file}
            )
        self.assertEqual(response.status_code, status_code)

    def test_sanitization_changes_filename_to_uuid(self):
        filepath = settings.BASE_DIR / "testapp/test_files/control.txt"
        with open(filepath, "rb") as file:
            response = self.client.post(
                reverse("test-sanitization"), {"uploaded_file": file}
            )
        self.assertEqual(response.status_code, 200)
        self.assertNotEqual(response.content, b"control.txt")

        uuid_pattern = (
            "^[0-9a-f]{8}-[0-9a-f]{4}-[0-5][0-9a-f]{3}-[089ab][0-9a-f]{3}-[0-9a-f]{12}$"
        )
        filename_without_extension = response.content.decode("utf-8").split(".")[0]
        self.assertTrue(re.match(uuid_pattern, filename_without_extension))


@unittest.skipUnless(SETTINGS_MODULE_NAME == "testproject.settings.keep_filename", "")
class TestSecureFileUploadKeepFilename(SimpleTestCase):
    """This test case specifically tests the keep_original_filename feature.

    As the effective upload configuration is finalized on Django startup, we
    need to test this feature with a separate "settings.py" configuration, since
    the "default" configuration defines keep_original_filename=False.
    """

    def test_sanitization_does_not_change_filename_to_uuid_if_keep_original_filename(
        self,
    ):
        filepath = settings.BASE_DIR / "testapp/test_files/control.txt"
        with open(filepath, "rb") as file:
            response = self.client.post(
                reverse("test-sanitization"), {"uploaded_file": file}
            )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.content, b"control.txt")


@unittest.skipUnless(SETTINGS_MODULE_NAME == "testproject.settings.use_clamav", "")
class TestSecureFileUploadClamavIntegration(SimpleTestCase):
    """This test case specifically tests the clamav feature, which uses the settings/clamav.py settings module."""

    @parameterized.expand(
        [
            ("control.txt", 200),
            ("malicious_file_eicar.com.txt", 403),
        ]
    )
    def test_clamav_flags_malicious_file(self, filename, status_code):
        filepath = settings.BASE_DIR / f"testapp/test_files/{filename}"
        with open(filepath, "rb") as file:
            response = self.client.post(reverse("test-clamav"), {"uploaded_file": file})
        self.assertEqual(response.status_code, status_code)


@unittest.skipUnless(SETTINGS_MODULE_NAME == "testproject.settings.use_yara", "")
class TestSecureFileUploadYaraIntegration(SimpleTestCase):
    """This test case specifically tests the clamav feature, which uses the settings/clamav.py settings module."""

    @parameterized.expand(
        [
            ("control.txt", 200),
            ("yara_test.txt", 403),
        ]
    )
    def test_clamav_flags_malicious_file(self, filename, status_code):
        filepath = settings.BASE_DIR / f"testapp/test_files/{filename}"
        with open(filepath, "rb") as file:
            response = self.client.post(reverse("test-yara"), {"uploaded_file": file})
        self.assertEqual(response.status_code, status_code)
