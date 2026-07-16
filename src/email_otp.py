#!/usr/bin/env python3
"""Poll an IMAP mailbox until an OTP code is found."""

from __future__ import annotations

import argparse
import email
import imaplib
import json
import re
import ssl
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from email.header import decode_header, make_header
from email.message import Message
from html.parser import HTMLParser


class HTMLStripper(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.parts: list[str] = []

    def handle_data(self, data: str) -> None:
        self.parts.append(data)

    def text(self) -> str:
        return " ".join(part.strip() for part in self.parts if part.strip())


@dataclass
class ImapConfig:
    host: str
    port: int
    username: str
    password: str
    mailbox: str
    use_ssl: bool
    sender_contains: str
    sender_contains_any: list[str]
    subject_contains: str
    subject_contains_any: list[str]
    subject_equals_any: list[str]
    body_contains_any: list[str]
    code_regex: str
    timeout_seconds: int
    poll_interval_seconds: int
    since_seconds: int
    max_scan_messages: int


def parse_args() -> ImapConfig:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config-json", required=True)
    args = parser.parse_args()
    raw = json.loads(args.config_json)
    return ImapConfig(
        host=raw["imapHost"],
        port=int(raw.get("imapPort", 993)),
        username=raw["imapUsername"],
        password=raw["imapPassword"],
        mailbox=raw.get("imapMailbox", "INBOX"),
        use_ssl=bool(raw.get("imapUseSsl", True)),
        sender_contains=raw.get("senderContains", ""),
        sender_contains_any=list(raw.get("senderContainsAny", [])),
        subject_contains=raw.get("subjectContains", ""),
        subject_contains_any=list(raw.get("subjectContainsAny", [])),
        subject_equals_any=list(raw.get("subjectEqualsAny", [])),
        body_contains_any=list(raw.get("bodyContainsAny", [])),
        code_regex=raw.get("codeRegex", r"\b(\d{6})\b"),
        timeout_seconds=int(raw.get("timeoutSeconds", 180)),
        poll_interval_seconds=int(raw.get("pollIntervalSeconds", 5)),
        since_seconds=int(raw.get("sinceSeconds", 900)),
        max_scan_messages=int(raw.get("maxScanMessages", 200)),
    )


def decode(value: str | bytes | None) -> str:
    if not value:
        return ""
    if isinstance(value, bytes):
        value = value.decode("utf-8", "replace")
    try:
        return str(make_header(decode_header(value)))
    except Exception:
        return value


def message_text(message: Message) -> str:
    texts: list[str] = []
    if message.is_multipart():
        for part in message.walk():
            content_type = part.get_content_type()
            disposition = (part.get("Content-Disposition") or "").lower()
            if "attachment" in disposition:
                continue
            payload = part.get_payload(decode=True)
            if payload is None:
                continue
            charset = part.get_content_charset() or "utf-8"
            body = payload.decode(charset, "replace")
            if content_type == "text/plain":
                texts.append(body)
            elif content_type == "text/html":
                stripper = HTMLStripper()
                stripper.feed(body)
                texts.append(stripper.text())
    else:
        payload = message.get_payload(decode=True)
        if payload:
            charset = message.get_content_charset() or "utf-8"
            body = payload.decode(charset, "replace")
            if message.get_content_type() == "text/html":
                stripper = HTMLStripper()
                stripper.feed(body)
                texts.append(stripper.text())
            else:
                texts.append(body)
    return "\n".join(texts)


def match_window(message: Message, cutoff: datetime) -> bool:
    date_header = message.get("Date")
    if not date_header:
        return True
    parsed = email.utils.parsedate_to_datetime(date_header)
    if parsed is None:
        return True
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed >= cutoff


def message_datetime(message: Message) -> datetime:
    date_header = message.get("Date")
    if not date_header:
        return datetime.fromtimestamp(0, tz=timezone.utc)
    parsed = email.utils.parsedate_to_datetime(date_header)
    if parsed is None:
        return datetime.fromtimestamp(0, tz=timezone.utc)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def subject_matches(config: ImapConfig, subject: str) -> bool:
    subject_l = subject.lower()
    if config.subject_equals_any:
        return any(subject_l == token.lower() for token in config.subject_equals_any)
    if config.subject_contains and config.subject_contains.lower() in subject_l:
        return True
    if config.subject_contains_any:
        return any(token.lower() in subject_l for token in config.subject_contains_any)
    return True


def extract_message_bytes(payload: object) -> bytes | None:
    """Extract raw RFC822 bytes from imaplib.fetch payload variants."""
    if payload is None:
        return None
    if isinstance(payload, (bytes, bytearray)):
        return bytes(payload)
    if isinstance(payload, tuple):
        # imaplib fetch returns (b'id (BODY[] {size}', b'<RFC822 message>')
        # The second element is the actual email; the first is IMAP metadata.
        if len(payload) >= 2 and isinstance(payload[1], (bytes, bytearray)):
            return bytes(payload[1])
        for item in payload:
            result = extract_message_bytes(item)
            if result:
                return result
        return None
    if isinstance(payload, list):
        for item in payload:
            result = extract_message_bytes(item)
            if result:
                return result
        return None
    return None


def poll_for_code(config: ImapConfig) -> str:
    cutoff = datetime.now(timezone.utc) - timedelta(seconds=config.since_seconds)
    deadline = time.time() + config.timeout_seconds
    pattern = re.compile(config.code_regex)
    context = ssl.create_default_context()
    attempt = 0

    while time.time() < deadline:
        attempt += 1
        remaining = max(0, int(deadline - time.time()))
        print(
            f"[otp-test] Poll {attempt}: checking {config.mailbox} for recent USCIS mail "
            f"({remaining}s remaining)",
            file=sys.stderr,
            flush=True,
        )
        if config.use_ssl:
            connection: imaplib.IMAP4 = imaplib.IMAP4_SSL(config.host, config.port, ssl_context=context)
        else:
            connection = imaplib.IMAP4(config.host, config.port)
            connection.starttls(ssl_context=context)
        try:
            connection.login(config.username, config.password)
            status, _ = connection.select(config.mailbox, readonly=True)
            if status != "OK":
                raise RuntimeError(f"Could not open mailbox {config.mailbox}")

            status, data = connection.search(None, "ALL")
            if status != "OK":
                raise RuntimeError("IMAP search failed")

            msg_ids = data[0].split()
            scan_limit = min(len(msg_ids), config.max_scan_messages)
            print(
                f"[otp-test] Mailbox opened, scanning up to {scan_limit} recent messages",
                file=sys.stderr,
                flush=True,
            )
            candidates: list[tuple[datetime, str, str, str]] = []
            all_emails_found: list[str] = []
            for msg_id in reversed(msg_ids[-scan_limit:]):
                try:
                    # msg_id is bytes, convert to string for fetch
                    msg_id_str = msg_id.decode() if isinstance(msg_id, bytes) else str(msg_id)
                except (AttributeError, TypeError) as e:
                    print(f"[otp-test] Error converting msg_id: {type(msg_id)} {msg_id} - {e}", file=sys.stderr, flush=True)
                    continue
                # Use BODY[] instead of RFC822 for iCloud IMAP compatibility
                status, payload = connection.fetch(msg_id_str, "(BODY.PEEK[])")
                if status != "OK" or not payload:
                    continue
                raw_bytes = extract_message_bytes(payload)
                if not raw_bytes:
                    print(
                        f"[otp-test] Could not extract raw bytes for msg_id={msg_id_str}; skipping",
                        file=sys.stderr,
                        flush=True,
                    )
                    continue
                message = email.message_from_bytes(raw_bytes)
                if not match_window(message, cutoff):
                    continue

                sender = decode(message.get("From"))
                subject = decode(message.get("Subject"))
                
                # Track this email for debugging
                all_emails_found.append(f"{msg_id_str}: from={sender[:50]!r} subject={subject[:60]!r}")

                sender_match = True
                if config.sender_contains:
                    sender_match = config.sender_contains.lower() in sender.lower()
                if not sender_match and config.sender_contains_any:
                    sender_match = any(token.lower() in sender.lower() for token in config.sender_contains_any)
                if not sender_match:
                    continue
                if not subject_matches(config, subject):
                    continue

                body = message_text(message)
                if config.body_contains_any and not any(token.lower() in body.lower() for token in config.body_contains_any):
                    continue

                haystack = "\n".join([subject, sender, body])
                matched = pattern.search(haystack)
                if matched:
                    code = matched.group(1) if matched.groups() else matched.group(0)
                    candidates.append((message_datetime(message), code, subject, sender))

            if candidates:
                candidates.sort(key=lambda item: item[0], reverse=True)
                chosen_at, code, subject, sender = candidates[0]
                print(
                    f"[otp-test] Found {len(candidates)} candidate code email(s); using latest "
                    f"from {chosen_at.isoformat()} subject={subject!r} sender={sender!r}",
                    file=sys.stderr,
                    flush=True,
                )
                print(code)
                return code

            # No matching codes found - log what we saw for debugging
            if all_emails_found:
                print(f"[otp-test] Scanned {len(all_emails_found)} emails, but NONE matched filters:", file=sys.stderr, flush=True)
                for email_summary in all_emails_found[:5]:  # Show first 5 for brevity
                    print(f"[otp-test]   {email_summary}", file=sys.stderr, flush=True)
                if len(all_emails_found) > 5:
                    print(f"[otp-test]   ... and {len(all_emails_found) - 5} more", file=sys.stderr, flush=True)
            else:
                print("[otp-test] No emails found in mailbox at all in the time window!", file=sys.stderr, flush=True)
            print("[otp-test] No matching verification code found in scanned messages", file=sys.stderr, flush=True)
        finally:
            try:
                connection.logout()
            except Exception:
                pass

        time.sleep(config.poll_interval_seconds)

    raise TimeoutError("Timed out waiting for OTP email")


def main() -> int:
    config = parse_args()
    try:
        poll_for_code(config)
        return 0
    except Exception as exc:
        import traceback
        traceback.print_exc(file=sys.stderr)
        print(str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
