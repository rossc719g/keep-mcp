"""Preserve annotations unknown to the pinned gkeepapi parser."""

from copy import deepcopy

from gkeepapi import node


class OpaqueAnnotation(node.Annotation):
    __slots__ = ("_raw",)

    def __init__(self, raw):
        super().__init__()
        self._raw = deepcopy(raw)
        self.id = raw.get("id") or self.id
        self._dirty = False

    def save(self, clean=True):
        return deepcopy(self._raw)


class PreservingNodeAnnotations(node.NodeAnnotations):
    @classmethod
    def from_json(cls, raw):
        if any(
            key in raw for key in ("webLink", "topicCategory", "taskAssist", "context")
        ):
            return super().from_json(raw)
        return OpaqueAnnotation(raw)


# gkeepapi 0.17.1 dereferences None for unknown types; retain their complete payload.
node.NodeAnnotations = PreservingNodeAnnotations
