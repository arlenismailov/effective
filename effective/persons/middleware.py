import jwt
from django.conf import settings
from django.http import JsonResponse
from .models import User

class JWTAuthenticationMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # Пропускаем аутентификацию для некоторых путей
        excluded_paths = ['/api/auth/register/', '/api/auth/login/', '/admin/']
        if any(request.path.startswith(path) for path in excluded_paths):
            return self.get_response(request)

        # Получаем токен из заголовка Authorization
        auth_header = request.META.get('HTTP_AUTHORIZATION')
        if not auth_header or not auth_header.startswith('Bearer '):
            return JsonResponse({'error': 'Токен не предоставлен'}, status=401)

        token = auth_header.split(' ')[1]
        
        try:
            # Декодируем JWT токен
            payload = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
            user_id = payload.get('user_id')
            
            if not user_id:
                return JsonResponse({'error': 'Неверный токен'}, status=401)
            
            # Получаем пользователя из БД
            try:
                user = User.objects.get(id=user_id, is_active=True)
                request.user = user
            except User.DoesNotExist:
                return JsonResponse({'error': 'Пользователь не найден'}, status=401)
                
        except jwt.ExpiredSignatureError:
            return JsonResponse({'error': 'Токен истек'}, status=401)
        except jwt.InvalidTokenError:
            return JsonResponse({'error': 'Неверный токен'}, status=401)
        except Exception as e:
            return JsonResponse({'error': 'Ошибка аутентификации'}, status=401)

        return self.get_response(request)
