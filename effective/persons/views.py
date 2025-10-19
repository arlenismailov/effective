from rest_framework import status, permissions
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from rest_framework.views import APIView
from django.contrib.auth import authenticate
from django.utils import timezone
from .models import User, Role, BusinessElement, AccessRoleRule, UserRole, Product, Order
from .serializers import (
    UserRegistrationSerializer, UserSerializer, UserUpdateSerializer, 
    LoginSerializer, RoleSerializer, BusinessElementSerializer,
    AccessRoleRuleSerializer, UserRoleSerializer, ProductSerializer, OrderSerializer
)
from .middleware import JWTAuthenticationMiddleware

class RegisterView(APIView):
    def post(self, request):
        serializer = UserRegistrationSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            # Назначаем роль "user" по умолчанию
            try:
                user_role = Role.objects.get(name='user')
                UserRole.objects.create(user=user, role=user_role)
            except Role.DoesNotExist:
                pass
            
            return Response({
                'message': 'Пользователь успешно зарегистрирован',
                'user': UserSerializer(user).data
            }, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class LoginView(APIView):
    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            password = serializer.validated_data['password']
            
            try:
                user = User.objects.get(email=email, is_active=True)
                if user.check_password(password):
                    token = user.generate_jwt_token()
                    return Response({
                        'message': 'Успешный вход в систему',
                        'token': token,
                        'user': UserSerializer(user).data
                    })
                else:
                    return Response({'error': 'Неверный пароль'}, status=status.HTTP_401_UNAUTHORIZED)
            except User.DoesNotExist:
                return Response({'error': 'Пользователь не найден'}, status=status.HTTP_401_UNAUTHORIZED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class LogoutView(APIView):
    def post(self, request):
        # В JWT токенах logout обычно обрабатывается на клиенте
        # Здесь можно добавить логику для blacklist токенов
        return Response({'message': 'Успешный выход из системы'})

class UserProfileView(APIView):
    def get(self, request):
        if not hasattr(request, 'user') or not request.user.is_authenticated:
            return Response({'error': 'Необходима аутентификация'}, status=status.HTTP_401_UNAUTHORIZED)
        
        return Response(UserSerializer(request.user).data)
    
    def put(self, request):
        if not hasattr(request, 'user') or not request.user.is_authenticated:
            return Response({'error': 'Необходима аутентификация'}, status=status.HTTP_401_UNAUTHORIZED)
        
        serializer = UserUpdateSerializer(request.user, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(UserSerializer(request.user).data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class UserDeleteView(APIView):
    def delete(self, request):
        if not hasattr(request, 'user') or not request.user.is_authenticated:
            return Response({'error': 'Необходима аутентификация'}, status=status.HTTP_401_UNAUTHORIZED)
        
        # Мягкое удаление
        request.user.is_active = False
        request.user.deleted_at = timezone.now()
        request.user.save()
        
        return Response({'message': 'Аккаунт успешно удален'})

# API для управления ролями и правами (только для админов)
class RoleListView(APIView):
    def get(self, request):
        if not hasattr(request, 'user') or not request.user.is_authenticated:
            return Response({'error': 'Необходима аутентификация'}, status=status.HTTP_401_UNAUTHORIZED)
        
        if not request.user.is_superuser:
            return Response({'error': 'Недостаточно прав'}, status=status.HTTP_403_FORBIDDEN)
        
        roles = Role.objects.all()
        serializer = RoleSerializer(roles, many=True)
        return Response(serializer.data)
    
    def post(self, request):
        if not hasattr(request, 'user') or not request.user.is_authenticated:
            return Response({'error': 'Необходима аутентификация'}, status=status.HTTP_401_UNAUTHORIZED)
        
        if not request.user.is_superuser:
            return Response({'error': 'Недостаточно прав'}, status=status.HTTP_403_FORBIDDEN)
        
        serializer = RoleSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class BusinessElementListView(APIView):
    def get(self, request):
        if not hasattr(request, 'user') or not request.user.is_authenticated:
            return Response({'error': 'Необходима аутентификация'}, status=status.HTTP_401_UNAUTHORIZED)
        
        if not request.user.is_superuser:
            return Response({'error': 'Недостаточно прав'}, status=status.HTTP_403_FORBIDDEN)
        
        elements = BusinessElement.objects.all()
        serializer = BusinessElementSerializer(elements, many=True)
        return Response(serializer.data)
    
    def post(self, request):
        if not hasattr(request, 'user') or not request.user.is_authenticated:
            return Response({'error': 'Необходима аутентификация'}, status=status.HTTP_401_UNAUTHORIZED)
        
        if not request.user.is_superuser:
            return Response({'error': 'Недостаточно прав'}, status=status.HTTP_403_FORBIDDEN)
        
        serializer = BusinessElementSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class AccessRuleListView(APIView):
    def get(self, request):
        if not hasattr(request, 'user') or not request.user.is_authenticated:
            return Response({'error': 'Необходима аутентификация'}, status=status.HTTP_401_UNAUTHORIZED)
        
        if not request.user.is_superuser:
            return Response({'error': 'Недостаточно прав'}, status=status.HTTP_403_FORBIDDEN)
        
        rules = AccessRoleRule.objects.all()
        serializer = AccessRoleRuleSerializer(rules, many=True)
        return Response(serializer.data)
    
    def post(self, request):
        if not hasattr(request, 'user') or not request.user.is_authenticated:
            return Response({'error': 'Необходима аутентификация'}, status=status.HTTP_401_UNAUTHORIZED)
        
        if not request.user.is_superuser:
            return Response({'error': 'Недостаточно прав'}, status=status.HTTP_403_FORBIDDEN)
        
        serializer = AccessRoleRuleSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

# Mock-объекты для демонстрации
class ProductListView(APIView):
    def get(self, request):
        if not hasattr(request, 'user') or not request.user.is_authenticated:
            return Response({'error': 'Необходима аутентификация'}, status=status.HTTP_401_UNAUTHORIZED)
        
        # Проверяем права доступа
        if not self._check_permission(request.user, 'products', 'read'):
            return Response({'error': 'Недостаточно прав для просмотра товаров'}, status=status.HTTP_403_FORBIDDEN)
        
        products = Product.objects.all()
        serializer = ProductSerializer(products, many=True)
        return Response(serializer.data)
    
    def post(self, request):
        if not hasattr(request, 'user') or not request.user.is_authenticated:
            return Response({'error': 'Необходима аутентификация'}, status=status.HTTP_401_UNAUTHORIZED)
        
        if not self._check_permission(request.user, 'products', 'create'):
            return Response({'error': 'Недостаточно прав для создания товаров'}, status=status.HTTP_403_FORBIDDEN)
        
        serializer = ProductSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save(owner=request.user)
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    def _check_permission(self, user, element_name, action):
        """Проверяет права пользователя на выполнение действия с элементом"""
        try:
            element = BusinessElement.objects.get(name=element_name)
            user_roles = UserRole.objects.filter(user=user)
            
            for user_role in user_roles:
                try:
                    rule = AccessRoleRule.objects.get(role=user_role.role, element=element)
                    if action == 'read' and rule.read_permission:
                        return True
                    elif action == 'create' and rule.create_permission:
                        return True
                    elif action == 'update' and rule.update_permission:
                        return True
                    elif action == 'delete' and rule.delete_permission:
                        return True
                except AccessRoleRule.DoesNotExist:
                    continue
        except BusinessElement.DoesNotExist:
            pass
        
        return False

class OrderListView(APIView):
    def get(self, request):
        if not hasattr(request, 'user') or not request.user.is_authenticated:
            return Response({'error': 'Необходима аутентификация'}, status=status.HTTP_401_UNAUTHORIZED)
        
        if not self._check_permission(request.user, 'orders', 'read'):
            return Response({'error': 'Недостаточно прав для просмотра заказов'}, status=status.HTTP_403_FORBIDDEN)
        
        orders = Order.objects.all()
        serializer = OrderSerializer(orders, many=True)
        return Response(serializer.data)
    
    def post(self, request):
        if not hasattr(request, 'user') or not request.user.is_authenticated:
            return Response({'error': 'Необходима аутентификация'}, status=status.HTTP_401_UNAUTHORIZED)
        
        if not self._check_permission(request.user, 'orders', 'create'):
            return Response({'error': 'Недостаточно прав для создания заказов'}, status=status.HTTP_403_FORBIDDEN)
        
        serializer = OrderSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save(user=request.user)
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    def _check_permission(self, user, element_name, action):
        """Проверяет права пользователя на выполнение действия с элементом"""
        try:
            element = BusinessElement.objects.get(name=element_name)
            user_roles = UserRole.objects.filter(user=user)
            
            for user_role in user_roles:
                try:
                    rule = AccessRoleRule.objects.get(role=user_role.role, element=element)
                    if action == 'read' and rule.read_permission:
                        return True
                    elif action == 'create' and rule.create_permission:
                        return True
                    elif action == 'update' and rule.update_permission:
                        return True
                    elif action == 'delete' and rule.delete_permission:
                        return True
                except AccessRoleRule.DoesNotExist:
                    continue
        except BusinessElement.DoesNotExist:
            pass
        
        return False
