from functools import wraps


def refresh_token_on_expiry(func):
    @wraps(func)
    def wrapper(self, *args, **kwargs):
        response = func(self, *args, **kwargs)
        if response.status_code == 452:
            self._auth_refresh_token()
            response = func(
                self, *args, **kwargs
            )
        return response

    return wrapper
