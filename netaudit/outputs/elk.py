from datetime import datetime
from elasticsearch import Elasticsearch
import uuid
from netaudit.types import ElasticSearchConfig, Report

def update_index(data : Report, config : ElasticSearchConfig):
    if not config:
        return
    es = Elasticsearch(hosts=config.host, basic_auth=config.basic_auth)
    doc = data.__dict__
    doc["timestamp"] = datetime.utcnow()
    es.index(index=config.index_name, id=uuid.uuid4().hex, document=doc)