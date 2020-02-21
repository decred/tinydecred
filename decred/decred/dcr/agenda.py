"""
Copyright (c) 2019-2020, Brian Stafford
Copyright (c) 2020, the Decred developers
See LICENSE for details
"""


class AgendaInfo:
    """
    Models data for deployments of a GetBlockChainInfoResult.
    """

    def __init__(self, status, since, startTime, expireTime):
        """
        Args:
            status (str): one of "defined", "started", "lockedin", "active",
                "failed".
            since (int): height of last state change.
            startTime (int): start time.
            expireTime (int): end time.
        """
        self.status = status
        self.since = since
        self.startTime = startTime
        self.expireTime = expireTime

    @staticmethod
    def parse(obj):
        """
        Parse the AgendaInfo from the decoded RPC response.

        Args:
            obj (dict): the decoded dcrd RPC response.

        Returns:
            AgendaInfo: the AgendaInfo.
        """
        return AgendaInfo(
            status=obj["status"],
            since=obj.get("since", 0),
            startTime=obj["starttime"],
            expireTime=obj["expiretime"],
        )


class AgendaChoices:
    """
    Agenda individual choices such as abstain, yes, no.
    """

    def __init__(self, id_, description, bits, isAbstain, isNo, count, progress):
        """
        Args:
            id_ (str): unique identifier of this choice.
            description (str): description of this choice.
            bits (int): bits that identify this choice.
            isAbstain (bool): this choice is to abstain from change.
            isNo (bool): hard no choice (1 and only 1 per agenda).
            count (int): how many votes received.
            progress (float): progress of the overall count.
        """
        self.id = id_
        self.description = description
        self.bits = bits
        self.isAbstain = isAbstain
        self.isNo = isNo
        self.count = count
        self.progress = progress

    def __eq__(self, other):
        try:
            return self.id == other.id
        except AttributeError:
            return False

    @staticmethod
    def parse(obj):
        """
        Parse the AgendaChoices from the decoded RPC response.

        Args:
            obj (dict): the decoded dcrd RPC response.

        Returns:
            AgendaChoices: the parsed AgendaChoices.
        """
        return AgendaChoices(
            id_=obj["id"],
            description=obj["description"],
            bits=obj["bits"],
            isAbstain=obj["isabstain"],
            isNo=obj["isno"],
            count=obj["count"],
            progress=obj["progress"],
        )


class Agenda:
    """
    An agenda with name, description, and its AgendaChoices.
    """

    def __init__(
        self,
        id_,
        description,
        mask,
        startTime,
        expireTime,
        status,
        quorumProgress,
        choices,
    ):
        """
        Args:
            id_ (str): unique identifier of this agenda.
            description (str): description of this agenda.
            mask (int): agenda mask.
            startTime (int): time agenda becomes valid.
            expireTime (int): time agenda becomes invalid.
            status (str): agenda status.
            quorumProgress (float): progress of quorum reached.
            choices list(AgendaChoices): all choices in this agenda.
        """
        self.id = id_
        self.description = description
        self.mask = mask
        self.startTime = startTime
        self.expireTime = expireTime
        self.status = status
        self.quorumProgress = quorumProgress
        self.choices = choices

    def __eq__(self, other):
        try:
            return self.id == other.id
        except AttributeError:
            return False

    @staticmethod
    def parse(obj):
        """
        Parse the Agenda from the decoded RPC response.

        Args:
            obj (dict): the decoded dcrd RPC response.

        Returns:
            Agenda: the parsed Agenda info.
        """
        return Agenda(
            id_=obj["id"],
            description=obj["description"],
            mask=obj["mask"],
            startTime=obj["starttime"],
            expireTime=obj["expiretime"],
            status=obj["status"],
            quorumProgress=obj["quorumprogress"],
            choices=[AgendaChoices.parse(choice) for choice in obj["choices"]],
        )


class AgendasInfo:
    """
    All current agenda information for the current network. agendas contains
    a list of Agenda.
    """

    def __init__(
        self,
        currentHeight,
        startHeight,
        endHeight,
        hash_,
        voteVersion,
        quorum,
        totalVotes,
        agendas,
    ):
        """
        Args:
            currentHeight (int): the current height.
            startHeight (int): the initial height.
            endHeight (int): the final height.
            hash_ (str): the hash.
            voteVersion (int): the vote version.
            quorum (float): the quorum.
            totalVotes (int): the total number of votes.
            agendas list(Agenda): all agendas in this AgendasInfo.
        """
        self.currentHeight = currentHeight
        self.startHeight = startHeight
        self.endHeight = endHeight
        self.hash = hash_
        self.voteVersion = voteVersion
        self.quorum = quorum
        self.totalVotes = totalVotes
        self.agendas = agendas

    @staticmethod
    def parse(obj):
        """
        Parse the AgendasInfo from the decoded RPC response.

        Args:
            obj (dict): the decoded dcrd RPC response.

        Returns:
            AgendasInfo: the AgendasInfo.
        """
        return AgendasInfo(
            currentHeight=obj["currentheight"],
            startHeight=obj["startheight"],
            endHeight=obj["endheight"],
            hash_=obj["hash"],
            voteVersion=obj["voteversion"],
            quorum=obj["quorum"],
            totalVotes=obj["totalvotes"],
            agendas=[Agenda.parse(agenda) for agenda in obj["agendas"]],
        )
