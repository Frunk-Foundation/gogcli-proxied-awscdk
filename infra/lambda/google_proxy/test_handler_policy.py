import unittest

import handler


class PolicyEngineTests(unittest.TestCase):
    def _ctx(
        self,
        *,
        method: str = "GET",
        host: str = "gmail.googleapis.com",
        path: str = "/gmail/v1/users/me/labels",
        query_keys=None,
        account_email: str = "jay@frunkholdings.ltd",
        request_size_bytes: int = 128,
    ):
        if query_keys is None:
            query_keys = []
        return {
            "caller_id": "caller-1",
            "account_email": account_email,
            "account_domain": account_email.split("@", 1)[1],
            "method": method,
            "host": host,
            "path": path,
            "query_keys": query_keys,
            "request_size_bytes": request_size_bytes,
            "request_id": "req-1",
        }

    def _normalize(self, doc, *, source="default", source_rank=0):
        return handler._normalize_policy_document(doc, source=source, source_rank=source_rank)

    def test_default_deny_when_no_rule_matches(self):
        policy = handler._merge_policy_documents(
            [
                self._normalize(
                    {
                        "version": 1,
                        "default_effect": "deny",
                        "rules": [
                            {
                                "id": "allow-reads",
                                "effect": "allow",
                                "match": {
                                    "methods": ["GET"],
                                    "path_regex": "^/gmail/v1/users/me/labels$",
                                },
                            }
                        ],
                    }
                )
            ]
        )

        decision = handler._evaluate_policy(policy, self._ctx(method="POST"))
        self.assertEqual("deny", decision["effect"])
        self.assertEqual("default_effect", decision["reason"])

    def test_allows_matching_read_rule(self):
        policy = handler._merge_policy_documents(
            [
                self._normalize(
                    {
                        "version": 1,
                        "default_effect": "deny",
                        "rules": [
                            {
                                "id": "gmail-read",
                                "effect": "allow",
                                "priority": 100,
                                "match": {
                                    "methods": ["GET"],
                                    "hosts": ["gmail.googleapis.com"],
                                    "path_regex": "^/gmail/v1/users/me/(labels|messages)(/.*)?$",
                                },
                            }
                        ],
                    }
                )
            ]
        )
        decision = handler._evaluate_policy(policy, self._ctx(path="/gmail/v1/users/me/messages"))
        self.assertEqual("allow", decision["effect"])
        self.assertEqual("gmail-read", decision["rule_id"])

    def test_deny_mutation_by_higher_priority(self):
        policy = handler._merge_policy_documents(
            [
                self._normalize(
                    {
                        "version": 1,
                        "default_effect": "deny",
                        "rules": [
                            {
                                "id": "allow-gmail-all",
                                "effect": "allow",
                                "priority": 10,
                                "match": {"hosts": ["gmail.googleapis.com"]},
                            },
                            {
                                "id": "deny-mutations",
                                "effect": "deny",
                                "priority": 100,
                                "match": {"methods": ["POST", "PUT", "PATCH", "DELETE"]},
                            },
                        ],
                    }
                )
            ]
        )
        decision = handler._evaluate_policy(policy, self._ctx(method="POST"))
        self.assertEqual("deny", decision["effect"])
        self.assertEqual("deny-mutations", decision["rule_id"])

    def test_forbidden_query_key_blocks(self):
        policy = handler._merge_policy_documents(
            [
                self._normalize(
                    {
                        "version": 1,
                        "default_effect": "deny",
                        "rules": [
                            {
                                "id": "allow-read-no-uploadtype",
                                "effect": "allow",
                                "priority": 100,
                                "match": {
                                    "methods": ["GET"],
                                    "query": {"forbid_keys": ["uploadtype"]},
                                },
                            },
                        ],
                    }
                )
            ]
        )
        decision = handler._evaluate_policy(policy, self._ctx(query_keys=["uploadtype"]))
        self.assertEqual("deny", decision["effect"])
        self.assertEqual("default_effect", decision["source"])

    def test_domain_constraint(self):
        policy = handler._merge_policy_documents(
            [
                self._normalize(
                    {
                        "version": 1,
                        "default_effect": "deny",
                        "rules": [
                            {
                                "id": "allow-domain-only",
                                "effect": "allow",
                                "match": {"methods": ["GET"]},
                                "constraints": {"require_account_domain": ["frunkholdings.ltd"]},
                            }
                        ],
                    }
                )
            ]
        )
        denied = handler._evaluate_policy(policy, self._ctx(account_email="jay@example.com"))
        self.assertEqual("deny", denied["effect"])
        allowed = handler._evaluate_policy(policy, self._ctx(account_email="jay@frunkholdings.ltd"))
        self.assertEqual("allow", allowed["effect"])

    def test_source_precedence_on_same_priority(self):
        default_doc = self._normalize(
            {
                "version": 1,
                "default_effect": "deny",
                "rules": [
                    {
                        "id": "default-allow",
                        "effect": "allow",
                        "priority": 50,
                        "match": {"methods": ["GET"], "hosts": ["gmail.googleapis.com"]},
                    }
                ],
            },
            source="default",
            source_rank=0,
        )
        account_doc = self._normalize(
            {
                "version": 1,
                "default_effect": "deny",
                "rules": [
                    {
                        "id": "account-deny",
                        "effect": "deny",
                        "priority": 50,
                        "match": {"methods": ["GET"], "hosts": ["gmail.googleapis.com"]},
                    }
                ],
            },
            source="account",
            source_rank=2,
        )
        policy = handler._merge_policy_documents([default_doc, account_doc])
        decision = handler._evaluate_policy(policy, self._ctx())
        self.assertEqual("deny", decision["effect"])
        self.assertEqual("account-deny", decision["rule_id"])

    def test_invalid_policy_unknown_key_fails_closed(self):
        with self.assertRaises(handler.ProxyError):
            self._normalize(
                {
                    "version": 1,
                    "default_effect": "deny",
                    "rules": [],
                    "unexpected": True,
                }
            )

    def test_load_effective_policy_merges_sources(self):
        original = handler._ssm_get_policy_json
        try:
            caller_id = "caller-a"
            account = "jay@frunkholdings.ltd"
            policy_prefix = "/gogcli-proxy/policy"
            store = {
                f"{policy_prefix}/default": {
                    "version": 1,
                    "default_effect": "deny",
                    "rules": [{"id": "base", "effect": "allow", "match": {"methods": ["GET"]}}],
                },
                f"{policy_prefix}/caller/{handler._b64url_nopad(caller_id)}": {
                    "version": 1,
                    "default_effect": "deny",
                    "rules": [{"id": "caller-rule", "effect": "allow", "priority": 10, "match": {"hosts": ["gmail.googleapis.com"]}}],
                },
                f"{policy_prefix}/account/{handler._b64url_nopad(account)}": {
                    "version": 1,
                    "default_effect": "deny",
                    "rules": [{"id": "account-rule", "effect": "deny", "priority": 20, "match": {"methods": ["POST"]}}],
                },
            }

            def fake_get(name):
                return store.get(name)

            handler._ssm_get_policy_json = fake_get
            policy = handler._load_effective_policy(policy_prefix, caller_id, account)
        finally:
            handler._ssm_get_policy_json = original

        decision = handler._evaluate_policy(policy, self._ctx(method="POST"))
        self.assertEqual("deny", decision["effect"])
        self.assertEqual("account-rule", decision["rule_id"])

    def test_load_effective_policy_requires_any_doc(self):
        original = handler._ssm_get_policy_json
        try:
            handler._ssm_get_policy_json = lambda _: None
            with self.assertRaises(handler.ProxyError):
                handler._load_effective_policy("/gogcli-proxy/policy", "caller-b", "jay@example.com")
        finally:
            handler._ssm_get_policy_json = original


if __name__ == "__main__":
    unittest.main()
