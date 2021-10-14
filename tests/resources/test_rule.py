from . import APIResourceBaseTestCase, APIResource

from tests.mock_utils import generic_200_mock


class RuleResourceTestCase(APIResourceBaseTestCase):
    @property
    def resource(self) -> APIResource:
        return self.df.Rule

    @generic_200_mock
    def test__aggregate_malware_behaviour(self, *args, **kwargs):
        response = self.resource.aggregate_malware_behaviour()
        self.assertEqual(200, response.code)
