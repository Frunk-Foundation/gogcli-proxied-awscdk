import unittest

import handler


class CallerIdentityTests(unittest.TestCase):
    def test_assumed_role_session_name_from_caller(self):
        event = {
            "requestContext": {
                "identity": {
                    "caller": "arn:aws:sts::123456789012:assumed-role/google-proxy-agent/agent-nilesoc-618bf570"
                }
            }
        }

        self.assertEqual("agent-nilesoc-618bf570", handler._caller_id(event))

    def test_assumed_role_session_name_from_user_arn_when_caller_missing(self):
        event = {
            "requestContext": {
                "identity": {
                    "userArn": "arn:aws:sts::123456789012:assumed-role/google-proxy-agent/agent-nilesoc-618bf570"
                }
            }
        }

        self.assertEqual("agent-nilesoc-618bf570", handler._caller_id(event))

    def test_assumed_role_session_name_from_caller_role_id_form(self):
        event = {
            "requestContext": {
                "identity": {
                    "caller": "AROA2DVGUO577DSQZOPJD:agent-nilesoc-618bf570"
                }
            }
        }

        self.assertEqual("agent-nilesoc-618bf570", handler._caller_id(event))

    def test_cognito_identity_id_still_wins(self):
        event = {
            "requestContext": {
                "identity": {
                    "cognitoIdentityId": "us-east-2:1234-5678",
                    "caller": "AROA2DVGUO577DSQZOPJD:agent-nilesoc-618bf570",
                }
            }
        }

        self.assertEqual("us-east-2:1234-5678", handler._caller_id(event))


if __name__ == "__main__":
    unittest.main()
