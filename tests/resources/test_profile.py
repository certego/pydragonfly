from . import APIResourceBaseTestCase, APIResource


class ProfileResourceTestCase(APIResourceBaseTestCase):
    @property
    def resource(self) -> APIResource:
        return self.df.Profile
