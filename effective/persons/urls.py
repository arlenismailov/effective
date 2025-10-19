from django.urls import path
from . import views

urlpatterns = [
    # Аутентификация
    path('auth/register/', views.RegisterView.as_view(), name='register'),
    path('auth/login/', views.LoginView.as_view(), name='login'),
    path('auth/logout/', views.LogoutView.as_view(), name='logout'),
    
    # Профиль пользователя
    path('auth/profile/', views.UserProfileView.as_view(), name='profile'),
    path('auth/delete/', views.UserDeleteView.as_view(), name='delete_user'),
    
    # Управление ролями и правами (только для админов)
    path('admin/roles/', views.RoleListView.as_view(), name='roles'),
    path('admin/elements/', views.BusinessElementListView.as_view(), name='elements'),
    path('admin/rules/', views.AccessRuleListView.as_view(), name='rules'),
    
    # Mock-объекты
    path('products/', views.ProductListView.as_view(), name='products'),
    path('orders/', views.OrderListView.as_view(), name='orders'),
]
