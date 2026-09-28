# Fill the Python code in this file
from test_data import *
from policy import POLICY


def json_search(key, input_object, role=None):
    """
    Search for a key recursively in a JSON object (nested dicts and lists)
    and return a list of matching {key: value} dicts, enforcing role-based
    access control based on policy.py.
    """
    # Enforce role-based access control based on policy.py
    if key in POLICY:
        allowed_roles = POLICY[key]
        if role is None:
            # Sensitive keys (e.g. apiKey, managementIpAddress) require explicit role permissions
            if "viewer" not in allowed_roles:
                return []
        elif role not in allowed_roles:
            return []

    ret_val = []

    def _recursive_search(obj):
        if isinstance(obj, dict):
            for k, v in obj.items():
                if k == key:
                    ret_val.append({k: v})
                if isinstance(v, (dict, list)):
                    _recursive_search(v)
        elif isinstance(obj, list):
            for item in obj:
                if isinstance(item, (dict, list)):
                    _recursive_search(item)

    _recursive_search(input_object)
    return ret_val


if __name__ == '__main__':
    print(json_search("issueSummary", data))
