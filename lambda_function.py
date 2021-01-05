import datetime
import json
import boto3
import uuid
import os

# import sechub + sts boto3 client
securityhub = boto3.client('securityhub')

def lambda_handler(event, context):
    #Import from CloudWatch Event
    print('Step1: Getting Account, Region, ContainerName and Tag from CWE...')
    awsAccount = str(event['account'])
    awsRegion = str(event['region'])
    containerName = str(event['detail']['repository-name'])
    containerTag = str(event['detail']['image-tags'][0])
    print(awsAccount,awsRegion,containerName,':',containerTag,' is detected..')

    # get scan result from Amazon ECR
    print('Step2: Start scanning Vulnerabilities from Amazon ECR...')
    ecr = boto3.client('ecr')
    response = ecr.describe_image_scan_findings(
    	repositoryName=containerName,
    	registryId=awsAccount,
    	imageId={
                'imageTag': containerTag
            },
        maxResults=1000
    )
    findings = response['imageScanFindings']['findings']

    # write Amazon ECR result included in CRITICAL, HIGH only
    print('Step3: Picking up CRITICAL and HIGH Severities from ECR result...')
    output = []
    for a in findings:
        if a['severity'] == 'CRITICAL' or a['severity'] == 'HIGH':
            output.append(a)
    print(containerName,' found : ', len(output), 'vulns from Amazon ECR Scanning.')

    # open Amazon ECR result vuln report & parse out vuln info
    try:
        if not output:
            print('No vulnerabilities.')
        else:
            print('Step4: Sending events as ASFF to Security Hub...')
            for p in output:
                cveId = str(p['name'])
                asffID = str(uuid.uuid4())
                cveDescription = str(p['description'])
                cveDescription = (cveDescription[:1021] + '..') if len(cveDescription) > 1021 else cveDescription
                ecrSeverity = str(p['severity'])
                cveReference = str(p['uri'])
                # Check attribute fields
                Att = {d['key']: d['value'] for d in p['attributes']}
                packageName = Att.get('package_name', 'None')
                installedVersion = Att.get('package_version', 'None')
                cvss2vector = Att.get('CVSS2_VECTOR', 'None')
                cvss2score = Att.get('CVSS2_SCORE', 'None')
                # create ISO 8601 timestamp
                iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                # map Amazon ECR severity to ASFF severity
                if ecrSeverity == 'INFORMATIONAL':
                    ecrProductSev = int(0)
                    ecrNormalizedSev = ecrProductSev * 10
                elif ecrSeverity == 'LOW':
                    ecrProductSev = int(1)
                    ecrNormalizedSev = ecrProductSev * 10
                elif ecrSeverity == 'MEDIUM':
                    ecrProductSev = int(4)
                    ecrNormalizedSev = ecrProductSev * 10
                elif ecrSeverity == 'HIGH':
                    ecrProductSev = int(7)
                    ecrNormalizedSev = ecrProductSev * 10
                elif ecrSeverity == 'CRITICAL':
                    ecrProductSev = int(9)
                    ecrNormalizedSev = ecrProductSev * 10
                else:
                    print('No vulnerability information found')
                try:
                    response = securityhub.batch_import_findings(
                        Findings=[
                            {
                                'SchemaVersion': '2018-10-08',
                                'Id': containerName + ':' + containerTag + '/' + cveId + '/' + packageName, 
                                'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccount + ':product/' + awsAccount + '/default',
                                'ProductFields': {
                                  'ProviderName': 'Amazon ECR',
                                  'ProviderVersion': 'v1.0',
                                  },
                                'GeneratorId': asffID,
                                'AwsAccountId': awsAccount,
                                'Types': [ 'Software and Configuration Checks/Vulnerabilities/CVE' ],
                                'CreatedAt': iso8601Time,
                                'UpdatedAt': iso8601Time,
                                'Severity': {
                                    'Product': ecrProductSev,
                                    'Normalized': ecrNormalizedSev
                                },
                                'Title': 'Amazon ECR found a vulnerability to ' + cveId + ' in ' + packageName + ' of container ' + containerName,
                                'Description': cveDescription,
                                'Remediation': {
                                    'Recommendation': {
                                        'Text': 'More information on this vulnerability is provided in the hyperlink',
                                        'Url': cveReference
                                    }
                                },
                                'Resources': [
                                    {
                                        'Type': 'Container',
                                        'Id': containerName + ':' + containerTag,
                                        'Partition': 'aws',
                                        'Region': awsRegion,
                                        'Details': {
                                            'Container': { 'ImageName': containerName + ':' + containerTag },
                                            'Other': {
                                                'CVE ID': cveId,
                                                'Installed Package': packageName + ' ' + installedVersion,
                                                'CVSS2 Vector': cvss2vector,
                                                'CVSS2 Score': cvss2score
                                            }
                                        }
                                    }
                                ],
                                'RecordState': 'ACTIVE'
                            }
                        ]
                    )
                    print(response)
                except Exception as e:
                    print(e)
                    raise
    except FileNotFoundError as err:
     print("The Vuln report could not be read because it does not exist.")
    except Exception as other:
     print("The Vuln report could not be read.")
