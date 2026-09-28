# Fill the Python code in this file
import unittest
from recursive_json_search import *
from test_data import *


class json_search_test(unittest.TestCase):
    '''test module to test search function in `recursive_json_search.py`'''

    def test_search_found(self):
        '''key should be found, return list should not be empty'''
        self.assertTrue([] != json_search(key1, data))

    def test_search_not_found(self):
        '''key should not be found, should return an empty list'''
        self.assertTrue([] == json_search(key2, data))

    def test_is_a_list(self):
        '''Should return a list'''
        self.assertIsInstance(json_search(key1, data), list)

    def test_wrong_role_cannot_read_secret(self):
        '''SR-1: viewer role cannot read apiKey secret'''
        self.assertEqual(json_search("apiKey", data, role="viewer"), [])

    def test_no_role_cannot_read_secret(self):
        '''SR-2: unauthenticated user (role=None) cannot read apiKey secret'''
        self.assertEqual(json_search("apiKey", data, role=None), [])

    def test_operator_cannot_read_apikey(self):
        '''SR-3: operator role cannot read apiKey (least privilege)'''
        self.assertEqual(json_search("apiKey", data, role="operator"), [])

    def test_admin_can_read_secret(self):
        '''SR-4: admin role can read apiKey secret'''
        self.assertTrue([] != json_search("apiKey", data, role="admin"))

    def test_viewer_can_read_summary(self):
        '''SR-5: viewer role can read public issueSummary'''
        self.assertTrue([] != json_search("issueSummary", data, role="viewer"))

    def test_operator_can_read_management_ip(self):
        '''operator role can read managementIpAddress'''
        self.assertTrue([] != json_search("managementIpAddress", data, role="operator"))

    def test_viewer_cannot_read_management_ip(self):
        '''viewer role cannot read managementIpAddress'''
        self.assertEqual(json_search("managementIpAddress", data, role="viewer"), [])


if __name__ == '__main__':
    unittest.main()
