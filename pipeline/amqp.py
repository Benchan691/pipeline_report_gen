import json
import logging

import pika

log = logging.getLogger(__name__)


def cloudamqp_url(cfg):
    return str(cfg.get("cloudamqp_url") or "").strip()


def cloudamqp_queue(cfg):
    return str(cfg.get("cloudamqp_queue") or "pipeline_transfer").strip() or "pipeline_transfer"


def require_cloudamqp_config(cfg):
    if not cloudamqp_url(cfg):
        raise ValueError("Missing transfer config: CLOUDAMQP_URL in .env")


def transfer_request_payload(folder_name, subject=None):
    folder = str(folder_name or "").strip()
    subject_text = str(subject or "").strip() or f"PIPELINE_UPLOAD:{folder}"
    return {"folder": folder, "subject": subject_text}


def publish_transfer_request(cfg, folder_name, subject=None):
    require_cloudamqp_config(cfg)
    queue = cloudamqp_queue(cfg)
    body = json.dumps(transfer_request_payload(folder_name, subject)).encode("utf-8")
    params = pika.URLParameters(cloudamqp_url(cfg))
    connection = pika.BlockingConnection(params)
    try:
        channel = connection.channel()
        channel.queue_declare(queue=queue, durable=True)
        channel.basic_publish(
            exchange="",
            routing_key=queue,
            body=body,
            properties=pika.BasicProperties(delivery_mode=2, content_type="application/json"),
        )
        log.info("Published transfer wake-up to queue=%s folder=%s", queue, folder_name)
    finally:
        connection.close()


def parse_transfer_request(body):
    if isinstance(body, (bytes, bytearray)):
        body = body.decode("utf-8")
    payload = json.loads(body or "{}")
    if not isinstance(payload, dict):
        raise ValueError("Transfer wake-up payload must be a JSON object")
    folder = str(payload.get("folder") or "").strip()
    subject = str(payload.get("subject") or "").strip()
    if not folder:
        raise ValueError("Transfer wake-up payload missing folder")
    if not subject:
        subject = f"PIPELINE_UPLOAD:{folder}"
    return folder, subject


def consume_transfer_requests(cfg, on_message):
    require_cloudamqp_config(cfg)
    queue = cloudamqp_queue(cfg)
    params = pika.URLParameters(cloudamqp_url(cfg))
    connection = pika.BlockingConnection(params)
    channel = connection.channel()
    channel.queue_declare(queue=queue, durable=True)
    channel.basic_qos(prefetch_count=1)

    def _callback(ch, method, _properties, body):
        delivery_tag = method.delivery_tag
        try:
            folder, subject = parse_transfer_request(body)
            log.info("Received transfer wake-up folder=%s subject=%s", folder, subject)
            on_message(folder, subject)
        except Exception:
            log.exception("Failed to process transfer wake-up")
            ch.basic_nack(delivery_tag=delivery_tag, requeue=True)
            return
        ch.basic_ack(delivery_tag=delivery_tag)

    channel.basic_consume(queue=queue, on_message_callback=_callback, auto_ack=False)
    log.info("Listening for transfer wake-ups on queue=%s (Ctrl+C to stop)", queue)
    try:
        channel.start_consuming()
    except KeyboardInterrupt:
        log.info("Stopping transfer listener")
    finally:
        if channel.is_open:
            channel.stop_consuming()
        if connection.is_open:
            connection.close()
