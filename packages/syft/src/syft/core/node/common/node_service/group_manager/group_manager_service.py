# stdlib
from typing import Callable
from typing import Dict
from typing import List
from typing import Type
from typing import Union

# third party
from nacl.encoding import HexEncoder
from nacl.signing import VerifyKey

# relative
from .....common.message import ImmediateSyftMessageWithReply
from ....domain.domain_interface import DomainInterface
from ...exceptions import AuthorizationError
from ...exceptions import GroupNotFoundError
from ...exceptions import MissingRequestKeyError
from ...node_table.utils import model_to_json
from ..auth import service_auth
from ..node_service import ImmediateNodeServiceWithReply
from .group_manager_messages import CreateGroupMessage
from .group_manager_messages import CreateGroupResponse
from .group_manager_messages import DeleteGroupMessage
from .group_manager_messages import DeleteGroupResponse
from .group_manager_messages import GetGroupMessage
from .group_manager_messages import GetGroupResponse
from .group_manager_messages import GetGroupsMessage
from .group_manager_messages import GetGroupsResponse
from .group_manager_messages import UpdateGroupMessage
from .group_manager_messages import UpdateGroupResponse

INPUT_TYPE = Union[
    Type[CreateGroupMessage],
    Type[UpdateGroupMessage],
    Type[GetGroupMessage],
    Type[GetGroupsMessage],
    Type[DeleteGroupMessage],
]

INPUT_MESSAGES = Union[
    CreateGroupMessage,
    UpdateGroupMessage,
    GetGroupMessage,
    GetGroupsMessage,
    DeleteGroupMessage,
]

OUTPUT_MESSAGES = Union[
    CreateGroupResponse,
    UpdateGroupResponse,
    GetGroupResponse,
    GetGroupsResponse,
    DeleteGroupResponse,
]


def create_group_msg(
    msg: CreateGroupMessage,
    node: DomainInterface,
    verify_key: VerifyKey,
) -> CreateGroupResponse:
    _current_user_id = msg.content.get("current_user", None)
    _group_name = msg.content.get("name", None)
    _users = msg.content.get("users", None)

    users = node.users

    if not _current_user_id:
        _current_user_id = users.first(
            verify_key=verify_key.encode(encoder=HexEncoder).decode("utf-8")
        ).id

    # Checks
    _is_allowed = node.users.can_create_groups(verify_key=verify_key)

    if not _group_name:
        raise MissingRequestKeyError("Invalid group name!")
    elif _is_allowed:
        node.groups.create(group_name=_group_name, users=_users)
    else:
        raise AuthorizationError("You're not allowed to create groups!")

    return CreateGroupResponse(
        address=msg.reply_to,
        status_code=200,
        content={"msg": "Group created successfully!"},
    )


def update_group_msg(
    msg: UpdateGroupMessage,
    node: DomainInterface,
    verify_key: VerifyKey,
) -> UpdateGroupResponse:
    _current_user_id = msg.content.get("current_user", None)
    _group_id = msg.content.get("group_id", None)
    _group_name = msg.content.get("name", None)
    _users = msg.content.get("users", None)

    users = node.users

    if not _current_user_id:
        _current_user_id = users.first(
            verify_key=verify_key.encode(encoder=HexEncoder).decode("utf-8")
        ).id

    # Checks
    _is_allowed = node.users.can_create_groups(verify_key=verify_key)

    if not node.groups.contain(id=_group_id):
        raise GroupNotFoundError("Group ID not found!")
    elif _is_allowed:
        node.groups.update(group_id=_group_id, group_name=_group_name, users=_users)
    else:
        raise AuthorizationError("You're not allowed to get this group!")

    return UpdateGroupResponse(
        address=msg.reply_to,
        status_code=200,
        content={"msg": "Group updated successfully!"},
    )


def get_group_msg(
    msg: GetGroupMessage,
    node: DomainInterface,
    verify_key: VerifyKey,
) -> GetGroupResponse:
    _current_user_id = msg.content.get("current_user", None)
    _group_id = msg.content.get("group_id", None)

    users = node.users

    if not _current_user_id:
        _current_user_id = users.first(
            verify_key=verify_key.encode(encoder=HexEncoder).decode("utf-8")
        ).id

    # Checks
    _is_allowed = node.users.can_create_groups(verify_key=verify_key)

    if not node.groups.contain(id=_group_id):
        raise GroupNotFoundError("Group ID not found!")
    elif _is_allowed:
        _group = node.groups.first(id=_group_id)
    else:
        raise AuthorizationError("You're not allowed to get this group!")

    _msg = model_to_json(_group)
    _msg["users"] = node.groups.get_users(group_id=_group_id)

    return GetGroupResponse(
        address=msg.reply_to,
        status_code=200,
        content=_msg,
    )


def get_all_groups_msg(
    msg: GetGroupsMessage,
    node: DomainInterface,
    verify_key: VerifyKey,
) -> GetGroupsResponse:

    try:
        _current_user_id = msg.content.get("current_user", None)
    except Exception:
        _current_user_id = None

    users = node.users

    if not _current_user_id:
        _current_user_id = users.first(
            verify_key=verify_key.encode(encoder=HexEncoder).decode("utf-8")
        ).id

    # Checks
    _is_allowed = node.users.can_create_groups(verify_key=verify_key)
    if _is_allowed:
        _groups = node.groups.all()
    else:
        raise AuthorizationError("You're not allowed to get the groups!")

    _groups = [model_to_json(group) for group in _groups]
    for group in _groups:
        group["users"] = node.groups.get_users(group_id=group["id"])

    return GetGroupsResponse(
        address=msg.reply_to,
        status_code=200,
        content=_groups,
    )


def del_group_msg(
    msg: DeleteGroupMessage,
    node: DomainInterface,
    verify_key: VerifyKey,
) -> DeleteGroupResponse:
    _current_user_id = msg.content.get("current_user", None)
    _group_id = msg.content.get("group_id", None)

    users = node.users

    if not _current_user_id:
        _current_user_id = users.first(
            verify_key=verify_key.encode(encoder=HexEncoder).decode("utf-8")
        ).id

    # Checks
    _is_allowed = node.users.can_create_groups(verify_key=verify_key)

    if not node.groups.contain(id=_group_id):
        raise GroupNotFoundError("Group ID not found!")
    elif _is_allowed:
        node.groups.delete_association(group=_group_id)
        node.groups.delete(id=_group_id)
    else:
        raise AuthorizationError("You're not allowed to delete this group!")

    return DeleteGroupResponse(
        address=msg.reply_to,
        status_code=200,
        content={"msg": "User deleted successfully!"},
    )


class GroupManagerService(ImmediateNodeServiceWithReply):
    msg_handler_map: Dict[INPUT_TYPE, Callable[..., OUTPUT_MESSAGES]] = {
        CreateGroupMessage: create_group_msg,
        UpdateGroupMessage: update_group_msg,
        GetGroupMessage: get_group_msg,
        GetGroupsMessage: get_all_groups_msg,
        DeleteGroupMessage: del_group_msg,
    }

    @staticmethod
    @service_auth(guests_welcome=True)
    def process(
        node: DomainInterface,
        msg: INPUT_MESSAGES,
        verify_key: VerifyKey,
    ) -> OUTPUT_MESSAGES:
        return GroupManagerService.msg_handler_map[type(msg)](
            msg=msg, node=node, verify_key=verify_key
        )

    @staticmethod
    def message_handler_types() -> List[Type[ImmediateSyftMessageWithReply]]:
        return [
            CreateGroupMessage,
            UpdateGroupMessage,
            GetGroupMessage,
            GetGroupsMessage,
            DeleteGroupMessage,
        ]
