from django.db import connection

TABLE = "items"


def count(request):
    connection.cursor().execute(f"SELECT COUNT(*) FROM {TABLE} WHERE owner = %s", [request.user.id])
