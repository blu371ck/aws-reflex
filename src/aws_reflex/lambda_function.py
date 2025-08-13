import json
import logging
from aws_reflex.factory import get_handler

logger = logging.getLogger(__name__)

def handler(event, context):
    for finding in event['detail']['service']['additionalInfo']['findings']:
        logger.info(f"Processing finding type: {finding.get('Type')}")

        handler_instance = get_handler(finding)

        if handler_instance:
            handler_instance.execute()
        else:
            logger.info(f"No handler configured for this finding type {finding.get('Type')}. Ignoring")
    
    return {'statusCode': 200, 'body': json.dumps('Processing complete.')}