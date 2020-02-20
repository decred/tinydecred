"""
Copyright (c) 2020, the Decred developers
See LICENSE for details
"""

from decred.dcr import agenda


AGENDA_INFO_RAW = dict(status="defined", since=1, starttime=2, expiretime=3,)
AGENDA_INFO_PARSED = AGENDA_INFO_RAW
AGENDA_INFO_ATTRS = (
    "status",
    "since",
    "startTime",
    "expireTime",
)


def test_agenda_info():
    do_test(
        agenda.AgendaInfo, AGENDA_INFO_RAW, AGENDA_INFO_PARSED, AGENDA_INFO_ATTRS,
    )


AGENDA_CHOICES_RAW = dict(
    id="choices_id",
    description="description",
    bits=0,
    isabstain=False,
    isno=False,
    count=0,
    progress=0.0,
)
AGENDA_CHOICES_PARSED = AGENDA_CHOICES_RAW
AGENDA_CHOICES_ATTRS = (
    "ID",
    "description",
    "bits",
    "isAbstain",
    "isNo",
    "count",
    "progress",
)


def test_agenda_choices():
    do_test(
        agenda.AgendaChoices,
        AGENDA_CHOICES_RAW,
        AGENDA_CHOICES_PARSED,
        AGENDA_CHOICES_ATTRS,
    )


AGENDA_RAW = dict(
    id="agenda_id",
    description="description",
    mask=0,
    starttime=0,
    expiretime=0,
    status="status",
    quorumprogress=0.0,
    choices=[AGENDA_CHOICES_RAW],
)
AGENDA_PARSED = dict(AGENDA_RAW)
AGENDA_PARSED["choices"] = [agenda.AgendaChoices.parse(AGENDA_CHOICES_RAW)]
AGENDA_ATTRS = (
    "ID",
    "description",
    "mask",
    "startTime",
    "expireTime",
    "status",
    "quorumProgress",
    "choices",
)


def test_agenda():
    do_test(
        agenda.Agenda, AGENDA_RAW, AGENDA_PARSED, AGENDA_ATTRS,
    )


AGENDAS_INFO_RAW = {
    "currentheight": 0,
    "startheight": 0,
    "endheight": 0,
    "hash": "hash",
    "voteversion": 0,
    "quorum": 0.0,
    "totalvotes": 0,
    "agendas": [AGENDA_RAW],
}
AGENDAS_INFO_PARSED = dict(AGENDAS_INFO_RAW)
AGENDAS_INFO_PARSED["agendas"] = [agenda.Agenda.parse(AGENDA_RAW)]
AGENDAS_INFO_ATTRS = (
    "currentHeight",
    "startHeight",
    "endHeight",
    "hash",
    "voteVersion",
    "quorum",
    "totalVotes",
    "agendas",
)


def test_agendas_info():
    do_test(
        agenda.AgendasInfo, AGENDAS_INFO_RAW, AGENDAS_INFO_PARSED, AGENDAS_INFO_ATTRS,
    )


def do_test(class_, raw, parsed, attrs):
    obj = class_.parse(raw)
    for attr in attrs:
        assert getattr(obj, attr) == parsed[attr.lower()]
