from pydragonfly.sdk.const import MALICIOUS, ANALYZED
from pydragonfly.sdk.resources.analysis import AnalysisResult, Analysis
from . import APIResourceBaseTestCase, APIResource
from unittest import TestCase, SkipTest


from tests.mock_utils import (
    generic_200_mock,
    generic_201_mock,
    generic_204_mock,
    if_mock_connections,
    patch,
    MockAPIResponse,
)

class AnalysisResultTestCase(TestCase):

    matched_rules_json = [{
        "rule" : "TestRule",
        "weight": 120,
    }]

    result_json = {
        "id": "12",
        "status": "ANALYZED",
        "evaluation": "MALICIOUS",
        "weight": 120,
        "malware_families": ["Ransomware", "Trojan"],
        "malware_behaviours": ["Crypt", "Test"],
        "reports":[
            {"id": 1,
             "error": "Internal error"}
        ]

    }

    patch("Analysis.retrieve", return_value=result_json)
    patch("Report.matched_rules", return_value=matched_rules_json)
    def test_populate(self):
        result = AnalysisResult(12)
        self.assertFalse(result.is_ready())
        self.assertEqual(result.id, 12)
        self.assertEqual(result.gui_url, Analysis.instance_url(12))
        result.populate()
        self.assertEqual(result.status, ANALYZED)
        self.assertEqual(result.evaluation, MALICIOUS)
        self.assertEqual(result.score, 100)
        self.assertEqual(result.malware_family, "Ransomware")
        self.assertEqual(result.malware_behaviours, ["Crypt"])
        self.assertEqual(result.errors, ["Internal error"])
        self.assertEqual(len(result.matched_rules), 1)
        self.assertEqual(result.matched_rules[0].name, "TestRule")
        self.assertEqual(result.matched_rules[0].weight, 100)



class AnalysisResourceTestCase(APIResourceBaseTestCase):
    @property
    def resource(self) -> APIResource:
        return self.df.Analysis

    @if_mock_connections(
        patch(
            "requests.Session.request",
            return_value=MockAPIResponse(
                {"id": 1, "malware_type": "DLL", "entry_points": []}, 201
            ),
        )
    )  # POST /api/sample
    @generic_201_mock  # POST /api/analysis
    def test__create(self, *args, **kwargs):
        response = self.resource.create(
            data=self.resource.CreateAnalysisRequestBody(profiles=[1]),
            sample_name="test.exe",
            sample_buffer=b"",
        )
        self.assertEqual(201, response.code)

    @generic_200_mock
    def test__aggregate_evaluations(self, *args, **kwargs):
        response = self.resource.aggregate_evaluations()
        self.assertEqual(200, response.code)

    @generic_200_mock
    def test__aggregate_status(self, *args, **kwargs):
        response = self.resource.aggregate_status()
        self.assertEqual(200, response.code)

    @generic_200_mock
    def test__aggregate_malware_families(self, *args, **kwargs):
        response = self.resource.aggregate_malware_families()
        self.assertEqual(200, response.code)

    @generic_200_mock
    def test__aggregate_malware_type(self, *args, **kwargs):
        response = self.resource.aggregate_malware_type()
        self.assertEqual(200, response.code)

    @generic_204_mock
    def test__revoke(self, *args, **kwargs):
        response = self.resource.revoke(object_id=self.object_id)
        self.assertEqual(204, response.code)

