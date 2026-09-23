"""notes/views.py - one of your own API views."""

from rest_framework.response import Response
from rest_framework.views import APIView


class NotesView(APIView):
    # No authentication_classes or permission_classes: the REST_FRAMEWORK
    # defaults apply, so the access cookie authenticates the request and
    # IsAuthenticated refuses anyone without one.

    def get(self, request):
        return Response({"user": request.user.get_username()})

    def post(self, request):
        return Response({"created_by": request.user.get_username()}, status=201)
