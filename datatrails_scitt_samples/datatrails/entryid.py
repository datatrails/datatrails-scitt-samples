"""Decode the entryid assuming it has been returned by the DataTrails service"""


def entryid_to_identity(entryid: str) -> str:
    """
    Convert a SCITT Entry ID to a DataTrails Event Identity
    """
    eventsplit = entryid.split("_events_")
    eventuuid = eventsplit[-1]

    bucketsplit = eventsplit[0].split("assets_")
    bucketuuid = bucketsplit[-1]

    return f"assets/{bucketuuid}/events/{eventuuid}"
