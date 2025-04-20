import base64
import json
import os
import requests
import time
import hmac
import hashlib
import logging
import functions_framework # Make sure this is imported

# Configure logging
logging.basicConfig(level=logging.INFO)

# --- Configuration ---
# Fetched from environment variables set in the Cloud Function
FEISHU_WEBHOOK_URL = ''
FEISHU_SECRET = os.environ.get('FEISHU_SECRET') # Will be None if not set

# --- Helper Functions ---
def gen_sign(timestamp, secret):
    """Generates the signature for Feishu webhook security if secret is provided"""
    if not secret:
        return ""
    string_to_sign = f'{timestamp}\n{secret}'
    hmac_code = hmac.new(string_to_sign.encode('utf-8'), digestmod=hashlib.sha256).digest()
    sign = base64.b64encode(hmac_code).decode('utf-8')
    return sign

def format_alert_message(alert_data):
    """Formats the GCP alert data into a readable string for Feishu."""
    try:
        incident = alert_data.get('incident', {})
        policy_name = incident.get('policy_name', 'N/A')
        summary = incident.get('summary', 'No summary provided.')
        state = incident.get('state', 'N/A').upper()
        incident_url = incident.get('url', '#') # Link to the incident in GCP Monitoring
        resource_display_name = incident.get('resource', {}).get('display_name', 'N/A')
        if not resource_display_name or resource_display_name == 'N/A':
             resource_display_name = incident.get('resource_name', 'N/A')

        status_icon = "🚨" if state == "OPEN" else "✅" if state == "CLOSED" else "❓"

        message = (
            f"{status_icon} **GCP Monitoring Alert: {state}**\n\n"
            f"**Policy:** {policy_name}\n"
            f"**Resource:** {resource_display_name}\n"
            f"**Summary:** {summary}\n\n"
            f"[View Incident in GCP]({incident_url})"
        )
        return message

    except Exception as e:
        logging.error(f"Error formatting alert data: {e}\nData: {alert_data}")
        return f"🚨 **GCP Monitoring Alert Received**\n\nError parsing details. Raw data:\n```\n{json.dumps(alert_data, indent=2)}\n```"


def send_feishu_message(webhook_url, secret, message_content):
    """Sends a formatted message (using Feishu 'post' type) to the webhook."""
    if not webhook_url:
        logging.error("FEISHU_WEBHOOK_URL environment variable not set.")
        return

    headers = {'Content-Type': 'application/json; charset=utf-8'}
    timestamp = str(int(time.time()))
    sign = gen_sign(timestamp, secret)

    payload = {
        "msg_type": "post",
        "content": {
            "post": {
                "zh_cn": {
                    "title": "GCP Monitoring Alert",
                    "content": [
                        [
                            {
                                "tag": "text",
                                "text": message_content
                            }
                        ]
                    ]
                }
            }
        }
    }

    if secret and sign:
        payload["timestamp"] = timestamp
        payload["sign"] = sign

    try:
        response = requests.post(webhook_url, headers=headers, data=json.dumps(payload))
        response.raise_for_status()
        result = response.json()
        if result.get("StatusCode") == 0 or result.get("code") == 0 or result.get("ok") == True :
            logging.info(f"Message sent successfully to Feishu. Response: {result}")
        else:
            logging.error(f"Failed to send message. Feishu response: {result}")
    except requests.exceptions.RequestException as e:
        logging.error(f"Error sending POST request to Feishu: {e}")
    except json.JSONDecodeError:
        logging.error(f"Error decoding Feishu response: {response.text}")
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")


# --- Cloud Function Entry Point ---
# Decorated for Pub/Sub trigger using CloudEvents format
@functions_framework.cloud_event
def process_pubsub_alert(cloud_event):
    """
    Background Cloud Function triggered by Pub/Sub using CloudEvents.
    Processes an alert notification from Google Cloud Monitoring.
    Args:
         cloud_event (cloudevents.http.CloudEvent): The CloudEvent object representing the
                                                    Pub/Sub message trigger.
    """
    # Extract the base64-encoded message data using the CloudEvents structure
    # *** This is the key change based on your snippet ***
    encoded_data = cloud_event.data.get("message", {}).get("data")

    if encoded_data:
        try:
            # Decode the Pub/Sub message data
            pubsub_message_data = base64.b64decode(encoded_data).decode('utf-8')
            logging.info(f"Received Pub/Sub message data: {pubsub_message_data}")

            # Parse the JSON payload from Monitoring
            alert_data = json.loads(pubsub_message_data)

            # Format the message for Feishu
            feishu_message = format_alert_message(alert_data)

            # Send the message
            send_feishu_message(FEISHU_WEBHOOK_URL, FEISHU_SECRET, feishu_message)

        except json.JSONDecodeError as e:
            logging.error(f"Error decoding JSON from Pub/Sub message: {e}")
        except Exception as e:
            logging.error(f"Error processing Pub/Sub message: {e}")
    else:
        logging.warning(f"Received CloudEvent without 'data.message.data' field: {cloud_event.data}")





