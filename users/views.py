from django.contrib.auth import authenticate
from django.contrib.auth.models import Group, User
from rest_framework import status, viewsets
from rest_framework.decorators import action
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken

from .serializers import (
    RoleSerializer,
    UserLoginSerializer,
    UserRegistrationSerializer,
    UserRoleUpdateSerializer,
    UserSerializer,
    UserUpdateSerializer,
)


def is_admin(user):
    return user.groups.filter(name="Admin").exists()


class UserViewSet(viewsets.ModelViewSet):
    queryset = User.objects.all()
    serializer_class = UserSerializer
    permission_classes = [IsAuthenticated]

    def get_permissions(self):
        if self.action == "register" or self.action == "login":
            return [AllowAny()]
        return [IsAuthenticated()]

    @action(detail=False, methods=["post"], permission_classes=[AllowAny])
    def register(self, request):
        serializer = UserRegistrationSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            refresh = RefreshToken.for_user(user)
            return Response(
                {
                    "message": "user registered successfully",
                    "user": UserSerializer(user).data,
                    "tokens": {
                        "refresh": str(refresh),
                        "access": str(refresh.access_token),
                    },
                },
                status=status.HTTP_201_CREATED,
            )
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    @action(detail=False, methods=["post"], permission_classes=[AllowAny])
    def login(self, request):
        serializer = UserLoginSerializer(data=request.data)
        if serializer.is_valid():
            username = serializer.validated_data["username"]
            password = serializer.validated_data["password"]
            user = authenticate(username=username, password=password)
            if user:
                refresh = RefreshToken.for_user(user)
                return Response(
                    {
                        "message": "login successful",
                        "user": UserSerializer(user).data,
                        "tokens": {
                            "refresh": str(refresh),
                            "access": str(refresh.access_token),
                        },
                    },
                    status=status.HTTP_200_OK,
                )
            return Response(
                {"error": "username or password is incorrect"},
                status=status.HTTP_401_UNAUTHORIZED,
            )
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    @action(detail=False, methods=["get"], permission_classes=[IsAuthenticated])
    def list_users(self, request):
        users = User.objects.all()
        serializer = UserSerializer(users, many=True)
        return Response(
            {"count": users.count(), "users": serializer.data},
            status=status.HTTP_200_OK,
        )

    @action(
        detail=True,
        methods=["put"],
        permission_classes=[IsAuthenticated],
        url_path="roles",
    )
    def update_user_roles(self, request, pk=None):
        if not is_admin(request.user):
            return Response(
                {"error": "you do not have permission to update roles"},
                status=status.HTTP_403_FORBIDDEN,
            )

        try:
            user = User.objects.get(pk=pk)
        except User.DoesNotExist:
            return Response(
                {"error": "user not found"}, status=status.HTTP_404_NOT_FOUND
            )

        serializer = UserRoleUpdateSerializer(data=request.data)
        if serializer.is_valid():
            roles = serializer.validated_data["roles"]
            user.groups.clear()
            for role_name in roles:
                group, _ = Group.objects.get_or_create(name=role_name)
                user.groups.add(group)

            return Response(
                {
                    "message": "user roles updated successfully",
                    "user": UserSerializer(user).data,
                },
                status=status.HTTP_200_OK,
            )
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    @action(
        detail=False,
        methods=["get"],
        permission_classes=[IsAuthenticated],
        url_path="roles/available",
    )
    def list_available_roles(self, request):
        roles = Group.objects.all()
        serializer = RoleSerializer(roles, many=True)
        return Response(
            {"count": roles.count(), "roles": serializer.data},
            status=status.HTTP_200_OK,
        )

    @action(
        detail=False,
        methods=["get", "put", "delete"],
        permission_classes=[IsAuthenticated],
    )
    def me(self, request):
        if request.method == "GET":
            serializer = UserSerializer(request.user)
            return Response(serializer.data, status=status.HTTP_200_OK)

        elif request.method == "PUT":
            serializer = UserUpdateSerializer(
                request.user, data=request.data, context={"request": request}
            )
            if serializer.is_valid():
                serializer.save()
                return Response(
                    {
                        "message": "user data updated successfully",
                        "user": serializer.data,
                    },
                    status=status.HTTP_200_OK,
                )
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        elif request.method == "DELETE":
            request.user.delete()
            return Response(
                {"message": "account deleted successfully"}, status=status.HTTP_200_OK
            )


class RoleViewSet(viewsets.ReadOnlyModelViewSet):

    queryset = Group.objects.all()
    serializer_class = RoleSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        if is_admin(self.request.user):
            return Group.objects.all()
        return Group.objects.none()

    def list(self, request, *args, **kwargs):
        if not is_admin(request.user):
            return Response(
                {"error": "you do not have permission to view roles"},
                status=status.HTTP_403_FORBIDDEN,
            )
        return super().list(request, *args, **kwargs)
