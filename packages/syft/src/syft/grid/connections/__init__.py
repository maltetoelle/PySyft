from typing import Any
from eventlet import event

def get_response(event: event.Event, timeout:float=0.1, max_timeout:float=100, default_return_value:Any=None):
    """
    Await either the response for a websocket event or print to console if the event timed out

    :param event: The websocket event
    :param timeout: How long, in seconds, to wait repeatedly till the event was received or the max timeout was reached, defaults to 0.1
    :param max_timeout: The maximum timeout to wait for the response of the event, defaults to 10
    :param default_return_value: The default value that is to be returned if the event timed out, defaults to None
    :return: The response of the event or the default return value if the event timed out
    """

    response = None
    timer = 0
    while response is None:
        if (timer + timeout > max_timeout):
            print("Answer timed out")
            return default_return_value
        else:
            timer += timeout
        response = event.wait(timeout=timeout)
    return response
    
