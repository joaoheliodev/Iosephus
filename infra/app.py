#!/usr/bin/env python3
import os

import aws_cdk as cdk

from iosephus_infra.stack import IosephusStack

app = cdk.App()
IosephusStack(
    app, "Iosephus",
    env=cdk.Environment(account=os.environ.get("CDK_DEFAULT_ACCOUNT"),
                        region=os.environ.get("CDK_DEFAULT_REGION")),
    description="Iosephus SOC: 1 EC2 com Docker (MySQL + MongoDB + API)",
)
cdk.Tags.of(app).add("projeto", "iosephus")
app.synth()
