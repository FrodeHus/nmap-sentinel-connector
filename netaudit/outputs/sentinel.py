import base64
from datetime import datetime
import hashlib
import hmac
import logging
import requests

from netaudit.types import LogAnalyticsConfig

log = logging.getLogger("rich")


def __build_signature(
    customer_id, shared_key, date, content_length, method, content_type, resource
):
    x_headers = "x-ms-date:" + date
    string_to_hash = (
        method
        + "\n"
        + str(content_length)
        + "\n"
        + content_type
        + "\n"
        + x_headers
        + "\n"
        + resource
    )
    bytes_to_hash = bytes(string_to_hash, "UTF-8")
    decoded_key = base64.b64decode(shared_key)
    encoded_hash = base64.b64encode(
        hmac.new(decoded_key, bytes_to_hash, digestmod=hashlib.sha256).digest()
    ).decode("utf-8")

    authorization = "SharedKey {}:{}".format(customer_id, encoded_hash)
    return authorization


def post_data(config : LogAnalyticsConfig, body):
    if not config:
        return
    
    method = "POST"
    content_type = "application/json"
    resource = "/api/logs"
    rfc1123date = datetime.utcnow().strftime("%a, %d %b %Y %H:%M:%S GMT")
    content_length = len(body)
    signature = __build_signature(
        config.workspace_id,
        config.shared_access_key,
        rfc1123date,
        content_length,
        method,
        content_type,
        resource,
    )
    uri = (
        "https://"
        + config.workspace_id
        + ".ods.opinsights.azure.com"
        + resource
        + "?api-version=2016-04-01"
    )

    headers = {
        "content-type": content_type,
        "Authorization": signature,
        "Log-Type": config.log_name,
        "x-ms-date": rfc1123date,
    }

    response = requests.post(uri, data=body, headers=headers)
    if response.status_code < 200 or response.status_code > 299:
        logging.error("unable to write: {0}".format(response.status_code))
