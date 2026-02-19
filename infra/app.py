#!/usr/bin/env python3

import aws_cdk as cdk

from stacks.google_proxy_api_substack import GoogleProxyApiStack


app = cdk.App()

GoogleProxyApiStack(
    app,
    "GogcliGoogleProxyApi",
    stage_name=app.node.try_get_context("stage_name") or "prod",
    ssm_prefix=app.node.try_get_context("ssm_prefix") or "/gogcli-proxy",
)

app.synth()

