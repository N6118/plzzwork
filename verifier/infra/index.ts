import * as pulumi from '@pulumi/pulumi'

import { S3StaticSite, StaticSiteArgs, StaticSiteOutputs } from '@affinityproject/pulumi-helpers'

const config = new pulumi.Config()

const staticSiteArgs: StaticSiteArgs = {
  websiteName: config.require('website-name'),
  environment: config.require('environment'),
  route53HostedZone: config.get('route53-hosted-zone') || 'affinity-project.org',
  certificateArn: config.get('certificate-arn'),
  createACMCert: config.getBoolean('create-acm-cert'),
  indexDocument: config.require('index-document'),
  siteDir: config.require('site-directory')
}

const site: S3StaticSite = new S3StaticSite(staticSiteArgs)

export const outputs: StaticSiteOutputs = site.up()
