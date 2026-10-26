from django.db import connection


def search(request):
    term = request.GET["q"]
    with connection.cursor() as cur:
        cur.execute("SELECT * FROM items WHERE name LIKE '%%%s%%'" % term)  # SINK sql
        return cur.fetchall()
