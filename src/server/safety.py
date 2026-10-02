"""Write authorization, revisions, and deliberate permanent deletion."""

import hashlib
import hmac
import json
import secrets
import time

from .storage import SafetyError

AI_LABEL = "AI"


def _without_dirty(value):
    if isinstance(value, dict):
        return {k: _without_dirty(v) for k, v in value.items() if k != "_dirty"}
    if isinstance(value, list):
        return [_without_dirty(v) for v in value]
    return value


def fingerprint(value) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def note_revision(note) -> str:
    def tree(node):
        data = _without_dirty(node.save(clean=False))
        if "labelIds" in data:
            data["labelIds"] = sorted(label.id for label in node.labels.all())
        if "shareRequests" in data:
            data["shareRequests"] = [
                item for item in data["shareRequests"] if isinstance(item, dict)
            ]
        return {
            "node": data,
            "children": sorted(
                (tree(child) for child in getattr(node, "children", [])),
                key=lambda x: x["node"]["id"],
            ),
        }

    return fingerprint(
        {
            "tree": tree(note),
            "labels": sorted((label.id, label.name) for label in note.labels.all()),
        }
    )


def label_revision(keep, label) -> str:
    return fingerprint(
        {
            "id": label.id,
            "name": label.name,
            "notes": sorted(
                (note.id, note_revision(note))
                for note in affected_notes(keep, label.id)
            ),
        }
    )


def affected_notes(keep, label_id):
    return [
        n for n in keep.all() if any(label.id == label_id for label in n.labels.all())
    ]


def can_modify_note(note) -> bool:
    return any(label.name == AI_LABEL for label in note.labels.all())


def require_revision(actual: str, expected: str) -> None:
    if not isinstance(expected, str) or not expected:
        raise SafetyError(
            "Read the note or label first and pass its revision as expected_revision. No change was sent."
        )
    if not hmac.compare_digest(actual, expected):
        raise SafetyError(
            "Conflict: the note or label changed since it was read. No change was sent. Read it again and review the newer state before requesting an edit."
        )


def check_target(keep, target: str, arguments: dict) -> None:
    if target == "note":
        note = keep.get(arguments["note_id"])
        if not note:
            raise SafetyError("Note not found. Read the current notes before editing.")
        if not can_modify_note(note):
            raise SafetyError(
                'This note cannot be modified because it lacks the exact "AI" label. Add that label yourself in Google Keep if you want to permit requested edits. The MCP cannot grant itself access.'
            )
        require_revision(note_revision(note), arguments["expected_revision"])
    elif target == "label":
        label = keep.getLabel(arguments["label_id"])
        if not label:
            raise SafetyError(
                "Label not found. Read the current labels before editing."
            )
        if label.name == AI_LABEL:
            raise SafetyError(
                'The global "AI" authorization label cannot be deleted through this server.'
            )
        if any(not can_modify_note(n) for n in affected_notes(keep, label.id)):
            raise SafetyError(
                'Deleting this label would change notes without the "AI" label. No change was sent.'
            )
        require_revision(label_revision(keep, label), arguments["expected_revision"])


class DeleteChallenges:
    def __init__(self, clock=time.monotonic):
        self.clock = clock
        self.pending = {}

    def confirm(self, target: tuple, token: str | None, permanent: bool):
        now = self.clock()
        self.pending = {
            key: value for key, value in self.pending.items() if value[1] > now
        }
        if token is None:
            if len(self.pending) >= 128:
                self.pending.pop(next(iter(self.pending)))
            issued = secrets.token_urlsafe(32)
            self.pending[issued] = (target, now + 60)
            alternatives = {
                "note": "Prefer archive_note or trash_note.",
                "label": "Prefer remove_label_from_note on selected notes.",
                "item": "Prefer update_list_item with checked=true to mark the item complete.",
            }
            return {
                "status": "confirmation_required",
                "confirmation_token": issued,
                "expires_in_seconds": 60,
                "message": "Nothing was deleted. "
                + alternatives[target[0]]
                + " Only if the user specifically requested permanent deletion, call this same tool again within 60 seconds with the same target and expected_revision, this confirmation_token, user_requested=true, and permanently_delete=true. Never confirm just to bypass this warning.",
            }
        issued = self.pending.pop(token, None)
        if permanent is not True or issued is None or issued[0] != target:
            raise SafetyError(
                "Permanent deletion was not confirmed for this exact target and revision, or the confirmation expired/was already used. Nothing was deleted. Start again only if the user specifically requested permanent deletion."
            )
        return None


delete_challenges = DeleteChallenges()
