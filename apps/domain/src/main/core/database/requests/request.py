# grid relative
from .. import BaseModel
from .. import db


class Request(BaseModel):
    """Request.

    Columns:
        id (Integer, Primary Key): Cycle ID.
        date (TIME): Start time.
        user_id (Integer, Foreign Key): ID of the User that created the request.
        user_name (String): Email of the User that created the request.
        object_id (String): Target object to change in permisions.
        reason (String): Motivation of the request.
        status (String): The status of the request, wich can be 'pending', 'accepted' or 'denied'.
        request_type (String): Wheter the type of the request is 'permissions' or 'budget'.
        verify_key (String): User Verify Key.
    """

    __tablename__ = "request"

    id = db.Column(db.String(255), primary_key=True)
    date = db.Column(db.DateTime())
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    user_name = db.Column(db.String(255))
    object_id = db.Column(db.String(255))
    reason = db.Column(db.String(255))
    status = db.Column(db.String(255), default="pending")
    request_type = db.Column(db.String(255))
    verify_key = db.Column(db.String(255))
    object_type = db.Column(db.String(255))
    tags = db.Column(db.JSON())

    def __str__(self) -> str:
        return f"< Request id : {self.id}, user: {self.user_id}, Date: {self.date}, Object: {self.object_id}, reason: {self.reason}, status: {self.status}, type: {self.type} >"
