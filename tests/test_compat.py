from copy import deepcopy

import gkeepapi

from server.compat import OpaqueAnnotation
from server.safety import note_revision


def test_unknown_annotation_survives_read_edit_and_revision_check():
    raw = gkeepapi.node.Note().save(clean=False)
    annotation = {
        "id": "future-1",
        "futureFeature": {"values": [1, {"text": "private"}]},
    }
    raw["annotationsGroup"] = {"annotations": [deepcopy(annotation)]}
    keep = gkeepapi.Keep()
    keep._parseNodes([raw])
    note = keep.get(raw["id"])
    assert isinstance(note.annotations.all()[0], OpaqueAnnotation)
    before = note_revision(note)
    saved = note.save(clean=False)
    assert saved["annotationsGroup"]["annotations"] == [annotation]
    saved["annotationsGroup"]["annotations"][0]["futureFeature"]["values"].append(2)
    assert note_revision(note) == before
    note.title = "An explicitly requested edit"
    assert note.save()["annotationsGroup"]["annotations"] == [annotation]
    changed = deepcopy(raw)
    changed["annotationsGroup"]["annotations"][0]["futureFeature"]["values"].append(3)
    keep._parseNodes([changed])
    assert note_revision(note) != before


def test_unknown_annotations_without_ids_are_all_preserved():
    raw = {"annotations": [{"futureA": {"x": 1}}, {"futureB": {"x": 2}}]}
    annotations = gkeepapi.node.NodeAnnotations()
    annotations.load(raw)
    assert len(annotations.all()) == 2
    assert annotations.save()["annotations"] == raw["annotations"]
    assert not annotations.dirty


def test_unknown_context_and_known_annotation_survive_together():
    raw = {
        "annotations": [
            {"id": "context", "context": {"futureContext": {"value": "private"}}},
            {"id": "known", "topicCategory": {"category": "BOOKS"}},
        ]
    }
    annotations = gkeepapi.node.NodeAnnotations()
    annotations.load(raw)
    saved = annotations.save()["annotations"]
    assert saved == raw["annotations"]
    assert annotations.category == gkeepapi.node.CategoryValue.Books
