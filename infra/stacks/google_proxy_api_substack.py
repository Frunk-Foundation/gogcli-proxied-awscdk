import os
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import aws_cdk as cdk
from aws_cdk import CfnOutput, Duration, RemovalPolicy, Stack
from aws_cdk import aws_apigateway as apigw
from aws_cdk import aws_iam as iam
from aws_cdk import aws_lambda as lambda_
from aws_cdk import aws_logs as logs
from aws_cdk.aws_lambda_python_alpha import PythonFunction
from constructs import Construct


@dataclass(frozen=True)
class GoogleProxyApiProps:
    stage_name: str = "prod"
    ssm_prefix: str = "/gogcli-proxy"
    lambda_timeout_seconds: int = 30
    lambda_memory_mb: int = 512


class GoogleProxyApi(Construct):
    """
    "Sub-stack" construct for the gogcli -> API Gateway -> Lambda -> Google APIs proxy.
    Intended to be embedded into a larger CDK stack later.
    """

    def __init__(self, scope: Construct, construct_id: str, *, props: GoogleProxyApiProps) -> None:
        super().__init__(scope, construct_id)

        lambda_entry = Path(__file__).resolve().parents[1] / "lambda" / "google_proxy"
        if not lambda_entry.exists():
            raise ValueError(f"lambda entry not found: {lambda_entry}")

        proxy_fn = PythonFunction(
            self,
            "GoogleProxyHandler",
            entry=str(lambda_entry),
            index="handler.py",
            handler="handler",
            runtime=lambda_.Runtime.PYTHON_3_11,
            timeout=Duration.seconds(props.lambda_timeout_seconds),
            memory_size=props.lambda_memory_mb,
            environment={
                "GOG_SSM_PREFIX": props.ssm_prefix,
                "GOG_POLICY_ENABLED": os.getenv("GOG_POLICY_ENABLED", "true"),
                "GOG_POLICY_SSM_PREFIX": os.getenv(
                    "GOG_POLICY_SSM_PREFIX",
                    f"{props.ssm_prefix.rstrip('/')}/policy",
                ),
                "GOG_POLICY_CACHE_TTL_SECONDS": os.getenv("GOG_POLICY_CACHE_TTL_SECONDS", "30"),
                "GOG_POLICY_EVENTS_ENABLED": os.getenv("GOG_POLICY_EVENTS_ENABLED", "false"),
                "GOG_POLICY_EVENT_BUS_ARN": os.getenv("GOG_POLICY_EVENT_BUS_ARN", ""),
                # Defaults can be overridden per-account via SSM JSON.
                "GOG_DEFAULT_SCOPES": os.getenv(
                    "GOG_DEFAULT_SCOPES",
                    ",".join(
                        [
                            "https://www.googleapis.com/auth/gmail.readonly",
                            "https://www.googleapis.com/auth/gmail.labels",
                            "https://www.googleapis.com/auth/gmail.settings.basic",
                            "https://www.googleapis.com/auth/gmail.modify",
                            "https://www.googleapis.com/auth/calendar",
                            "https://www.googleapis.com/auth/drive",
                            "https://www.googleapis.com/auth/documents",
                            "https://www.googleapis.com/auth/spreadsheets",
                            "https://www.googleapis.com/auth/tasks",
                            "https://www.googleapis.com/auth/chat.bot",
                            "https://www.googleapis.com/auth/classroom.courses.readonly",
                            "https://www.googleapis.com/auth/classroom.rosters.readonly",
                            "https://www.googleapis.com/auth/classroom.coursework.me.readonly",
                            "https://www.googleapis.com/auth/classroom.coursework.students.readonly",
                            "https://www.googleapis.com/auth/script.projects",
                            "https://www.googleapis.com/auth/forms.body",
                            "https://www.googleapis.com/auth/forms.responses.readonly",
                            "https://www.googleapis.com/auth/keep.readonly",
                            "https://www.googleapis.com/auth/cloud-identity.groups.readonly",
                            "https://www.googleapis.com/auth/contacts.readonly",
                            "https://www.googleapis.com/auth/directory.readonly",
                            "https://www.googleapis.com/auth/userinfo.email",
                        ]
                    ),
                ),
            },
        )

        # SSM reads (allowlist + Google credentials). Narrow this down by prefix.
        prefix = props.ssm_prefix.rstrip("/")
        stack = Stack.of(self)
        proxy_fn.add_to_role_policy(
            iam.PolicyStatement(
                actions=["ssm:GetParameter", "ssm:GetParameters"],
                resources=[
                    f"arn:aws:ssm:{stack.region}:{stack.account}:parameter{prefix}/allow/*",
                    f"arn:aws:ssm:{stack.region}:{stack.account}:parameter{prefix}/google/accounts/*",
                    f"arn:aws:ssm:{stack.region}:{stack.account}:parameter{prefix}/policy/*",
                ],
            )
        )

        event_bus_arn = (os.getenv("GOG_POLICY_EVENT_BUS_ARN") or "").strip()
        if event_bus_arn != "":
            proxy_fn.add_to_role_policy(
                iam.PolicyStatement(
                    actions=["events:PutEvents"],
                    resources=[event_bus_arn],
                )
            )

        access_logs = logs.LogGroup(
            self,
            "AccessLogs",
            retention=logs.RetentionDays.ONE_MONTH,
            removal_policy=RemovalPolicy.DESTROY,
        )

        api = apigw.RestApi(
            self,
            "GoogleProxyApi",
            rest_api_name="gogcli-google-proxy",
            deploy_options=apigw.StageOptions(
                stage_name=props.stage_name,
                metrics_enabled=True,
                logging_level=apigw.MethodLoggingLevel.INFO,
                data_trace_enabled=False,
                access_log_destination=apigw.LogGroupLogDestination(access_logs),
                access_log_format=apigw.AccessLogFormat.json_with_standard_fields(
                    caller=True,
                    http_method=True,
                    ip=True,
                    protocol=True,
                    request_time=True,
                    resource_path=True,
                    response_length=True,
                    status=True,
                    user=True,
                ),
            ),
            # Allows Lambda to base64 responses for arbitrary Google content-types.
            binary_media_types=["*/*"],
            endpoint_types=[apigw.EndpointType.REGIONAL],
        )

        integration = apigw.LambdaIntegration(proxy_fn, proxy=True)

        # Root path (optional) and greedy proxy.
        api.root.add_method(
            "ANY",
            integration,
            authorization_type=apigw.AuthorizationType.IAM,
            api_key_required=True,
        )
        api.root.add_resource("{proxy+}").add_method(
            "ANY",
            integration,
            authorization_type=apigw.AuthorizationType.IAM,
            api_key_required=True,
        )

        api_key = apigw.ApiKey(self, "ClientApiKey", enabled=True)
        plan = api.add_usage_plan(
            "UsagePlan",
            name="gogcli-proxy",
            throttle=apigw.ThrottleSettings(rate_limit=50, burst_limit=100),
        )
        plan.add_api_key(api_key)
        plan.add_api_stage(api=api, stage=api.deployment_stage)

        self.api = api
        self.api_key = api_key
        self.lambda_fn = proxy_fn


class GoogleProxyApiStack(Stack):
    """
    Small wrapper stack so this construct can be deployed standalone.
    """

    def __init__(
        self,
        scope: Construct,
        construct_id: str,
        *,
        stage_name: str,
        ssm_prefix: str,
        env: Optional[cdk.Environment] = None,
        **kwargs,
    ) -> None:
        super().__init__(scope, construct_id, env=env, **kwargs)

        api = GoogleProxyApi(
            self,
            "Proxy",
            props=GoogleProxyApiProps(stage_name=stage_name, ssm_prefix=ssm_prefix),
        )

        CfnOutput(self, "ProxyBaseUrl", value=api.api.url)
        CfnOutput(self, "ApiKeyId", value=api.api_key.key_id)
