from . import APIResourceBaseTestCase, APIResource

from tests.mock_utils import generic_200_mock, generic_201_mock, generic_204_mock


class AnalysisResourceTestCase(APIResourceBaseTestCase):
    @property
    def resource(self) -> APIResource:
        return self.df.Analysis

    @generic_201_mock
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
