def entryid_to_identity(entryid: str) -> str:
    """
    Convert a SCITT Entry ID to a DataTrails Event Identity
    """
    eventsplit = entryid.split("_events_")
    eventUUID = eventsplit[-1]

    bucketsplit = eventsplit[0].split("assets_")
    bucketUUID = bucketsplit[-1]

    return f"assets/{bucketUUID}/events/{eventUUID}"
