from django.db import connection


def search(request):
    term = request.POST.get("q")
    sql = "SELECT * FROM items WHERE name = '{}'".format(term)
    connection.cursor().execute(sql)  # SINK sql
