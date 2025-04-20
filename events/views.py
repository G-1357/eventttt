from django.shortcuts import render, redirect, get_object_or_404
from .forms import LoginForm, EventForm
from rest_framework import generics
from .models import Event, User
from .serializers import EventSerializer, UserSerializer
from django.contrib import messages
from django.contrib.auth import authenticate, login
from django.contrib.auth.decorators import login_required
from django.contrib.auth.views import LogoutView
from django.urls import reverse
from django.contrib.auth.models import User
from django.contrib.auth.mixins import UserPassesTestMixin
from django.contrib.auth import login as django_login
import requests
import base64
import json
from django import forms


def decode_jwt(token):
    try:
        parts = token.split('.')
        if len(parts) != 3:
            raise ValueError("Неверный формат токена")

        payload = parts[1]
        padding = '=' * (4 - len(payload) % 4)
        decoded_bytes = base64.urlsafe_b64decode(payload + padding)
        decoded_str = decoded_bytes.decode('utf-8')

        return json.loads(decoded_str)
    except Exception as e:
        print(f"Ошибка при расшифровке токена: {e}")
        return None


def start(request):
    return render(request, 'start.html')


class LoginForm(forms.Form):
    login = forms.CharField(max_length=100)
    password = forms.CharField(widget=forms.PasswordInput)


def enter(request):
    form = LoginForm()
    if request.method == 'POST':
        form = LoginForm(request.POST)
        if form.is_valid():
            login = form.cleaned_data['login']
            password = form.cleaned_data['password']

            data = {
                'login': login,
                'password': password
            }

            headers = {
                'X-Request-Source': 'web',
                'Accept': 'application/json'
            }

            try:
                response = requests.post('http://37.9.4.22:8080/api/auth/sign-in', json=data, headers=headers)
                response.raise_for_status()

                token = response.text.strip()
                if token:
                    request.session['auth_token'] = token
                    decoded_token = decode_jwt(token)
                    if decoded_token:
                        user_data = decoded_token.get('data', {})
                        external_id = user_data.get('externalId')

                        if external_id:
                            user_info_response = requests.get(f'http://37.9.4.22:8080/api/users')
                            if user_info_response.status_code == 200:
                                user_info = user_info_response.json()
                                user_data['name'] = user_info.get('name', 'Неизвестно')
                                user_data['surname'] = user_info.get('surname', 'Неизвестно')
                                user_data['emails'] = user_info.get('emails', [])
                                user_data['phones'] = user_info.get('phones', [])

                        request.session['user_data'] = user_data
                        login_name = user_data.get('login') or decoded_token.get('sub')

                        if login_name:
                            user, created = User.objects.get_or_create(username=login_name)
                            django_login(request, user)

                        messages.success(request, 'Вы успешно вошли в систему!')
                        return redirect('profile')
                    else:
                        messages.error(request, 'Не удалось декодировать токен.')
                else:
                    messages.error(request, 'Не удалось получить токен авторизации.')
            except requests.exceptions.RequestException as e:
                messages.error(request, f'Ошибка сети: {e}')
            except ValueError as e:
                messages.error(request, f'Ошибка разбора ответа: {e}')

    return render(request, 'enter.html', {'form': form})


def forma(request):
    if request.method == 'POST':
        form = EventForm(request.POST, request.FILES)
        if form.is_valid():
            event = form.save(commit=False)
            event.organizer = request.user
            event.save()

            token = request.session.get('auth_token')
            user_data = request.session.get('user_data', {})
            roles = user_data.get('roles', [])

            if token and ('CREATOR' in roles or 'ADMIN' in roles):
                external_event_data = {
                    "annotation": event.description[:100],
                    "category": 1,
                    "description": event.description,
                    "eventDate": event.date.isoformat(),
                    "location": "Не указано",
                    "paid": False,
                    "participantLimit": 0,
                    "requestModeration": True,
                    "title": event.title
                }

                headers = {
                    'Authorization': f"Bearer Bearer {token}",
                    'Content-Type': 'application/json',
                    'Accept': 'application/json'
                }

                try:
                    response = requests.post('http://37.9.4.22:8080/api/creator/events', json=external_event_data,
                                             headers=headers)
                    response.raise_for_status()
                except requests.exceptions.RequestException as e:
                    print(f"Ошибка при отправке на сервер: {e}")

            return redirect('profile')
    else:
        form = EventForm()
    return render(request, 'forma.html', {'form': form})


def profile(request):
    user_data = {}
    events = []

    if request.user.is_authenticated:
        token = request.session.get('auth_token')
        decoded_token = decode_jwt(token)

        if decoded_token:
            user_data = request.session.get('user_data', {})
            user_data['login'] = decoded_token.get('sub', 'Неизвестно')
            user_data['name'] = user_data.get('name', 'Неизвестно')
            user_data['surname'] = user_data.get('surname', 'Неизвестно')
            user_data['emails'] = user_data.get('emails', [])
            user_data['phones'] = user_data.get('phones', [])

            external_id = user_data.get('externalId')
            if external_id:
                try:
                    response = requests.get(f'http://37.9.4.22:8080/api/users', headers={
                        'Authorization': f"Bearer Bearer {token}",
                    })
                    response.raise_for_status()
                    user_info = response.json()

                    user_data['name'] = user_info.get('name', user_data['name'])
                    user_data['surname'] = user_info.get('surname', user_data['surname'])
                    user_data['emails'] = user_info.get('emails', user_data['emails'])
                    user_data['phones'] = user_info.get('phones', user_data['phones'])

                except requests.exceptions.RequestException as e:
                    print(f"Ошибка при получении данных пользователя: {e}")

            events = Event.objects.filter(organizer=request.user)
        else:
            user_data['login'] = 'Ошибка получения данных'
            user_data['name'] = 'Ошибка получения данных'
            user_data['surname'] = 'Ошибка получения данных'
    else:
        user_data = {
            'login': 'Гость',
            'name': 'Неизвестно',
            'surname': 'Неизвестно',
            'emails': [],
            'phones': []
        }

    context = {
        'data': user_data,
        'events': events
    }
    return render(request, 'profile.html', context)


def event_creation_view(request):
    if request.method == "POST":
        title = request.POST.get('title')
        date = request.POST.get('date')
        description = request.POST.get('description')
        image = request.FILES.get('image')

        if title and date and description:
            event = Event(
                title=title,
                date=date,
                description=description,
                image=image,
                organizer=request.user
            )
            event.organizer_id = 1
            event.save()
            return redirect('profile')
        else:
            return render(request, 'event_form.html', {'error': 'Заполните все обязательные поля.'})
    else:
        return render(request, 'event_form.html')


def organizer_profile_view(request):
    events = Event.objects.filter(organizer=request.user)
    return render(request, 'organizer_profile.html', {
        'organizer_name': request.user.username,
        'organizer_email': request.user.email,
        'events': events
    })


# requests.post()

def event_detail(request, event_id):
    event = get_object_or_404(Event, id=event_id)
    context = {
        'event': event,
    }
    return render(request, 'event_detail.html', context)


# requests.post()

class EventListCreateAPIView(generics.ListCreateAPIView):
    queryset = Event.objects.all()
    serializer_class = EventSerializer


class EventDetailAPIView(generics.RetrieveUpdateDestroyAPIView):
    queryset = Event.objects.all()
    serializer_class = EventSerializer


def register_attendee(request, event_id):
    event = get_object_or_404(Event, id=event_id)
    if request.method == "POST":
        event.attendee_count += 1
        event.save()
        messages.success(request, f'К вашему мероприятию "{event.title}" зарегистрировался новый участник.')

        return redirect('event_detail', event_id=event.id)


def edit_event(request, event_id):
    event = get_object_or_404(Event, id=event_id)

    if request.method == "POST":
        form = EventForm(request.POST, request.FILES, instance=event)
        if form.is_valid():
            form.save()
            messages.success(request, 'Мероприятие успешно обновлено!')
            return redirect('profile', event_id=event.id)
    else:
        form = EventForm(instance=event)

    return render(request, 'edit_event.html', {'form': form, 'event': event})


def delete_event(request, event_id):
    event = get_object_or_404(Event, id=event_id)

    if request.method == "POST":
        event.delete()
        messages.success(request, 'Мероприятие успешно удалено!')
        return redirect('profile')

    return render(request, 'delete_event.html', {'event': event})


@login_required
def edit_event(request, event_id):
    event = get_object_or_404(Event, id=event_id)

    if request.method == "POST":
        form = EventForm(request.POST, request.FILES, instance=event)
        if form.is_valid():
            form.save()
            messages.success(request, 'Мероприятие успешно обновлено!')
            return redirect('event_detail', event_id=event.id)
    else:
        form = EventForm(instance=event)

    return render(request, 'edit_event.html', {'form': form, 'event': event})


@login_required
def delete_event(request, event_id):
    event = get_object_or_404(Event, id=event_id)

    if request.method == "POST":
        event.delete()
        messages.success(request, 'Мероприятие успешно удалено!')
        return redirect('profile')

    return render(request, 'delete_event.html', {'event': event})


def register(request):
    if request.method == 'POST':
        login = request.POST.get('login')
        password = request.POST.get('password')

        if not login or not password:
            messages.error(request, "Логин и пароль обязательны для регистрации.")
            return render(request, 'registration.html')

        data = {
            'login': login,
            'password': password
        }

        headers = {
            'X-Request-Source': 'web',
            'Accept': 'application/json',
        }

        try:
            response = requests.post('http://37.9.4.22:8080/api/auth/sign-up', json=data, headers=headers)
            response.raise_for_status()

            print(f"Ответ от сервера: {response.text}")

            if response.status_code == 200:
                response_data = response.json()
                token = response_data.get('token')

                if token:
                    request.session['auth_token'] = token
                    print(f"Токен сохранен в сессии: {token}")

                    decoded_token = decode_jwt(token)
                    if decoded_token:
                        user_data = decoded_token.get('data', {})
                        external_id = user_data.get('externalId')

                        if external_id:
                            user_info_response = requests.get(f'http://37.9.4.22:8080/api/users/{external_id}')
                            if user_info_response.status_code == 200:
                                user_info = user_info_response.json()
                                user_data['name'] = user_info.get('name', 'Неизвестно')
                                user_data['surname'] = user_info.get('surname', 'Неизвестно')
                                user_data['emails'] = user_info.get('emails', [])
                                user_data['phones'] = user_info.get('phones', [])
                            else:
                                user_data['name'] = 'Ошибка получения данных'
                                user_data['surname'] = 'Ошибка получения данных'

                        request.session['user_data'] = user_data

                        login_name = user_data.get('login') or decoded_token.get('sub')
                        if login_name:
                            user, created = User.objects.get_or_create(username=login_name)
                            django_login(request, user)

                        messages.success(request, 'Вы успешно вошли в систему!')
                        return redirect('profile')
                    else:
                        messages.error(request, 'Не удалось декодировать токен.')
                else:
                    messages.error(request, 'Не удалось получить токен авторизации.')
            else:
                messages.error(request, f'Ошибка при авторизации: {response.status_code}')
        except requests.exceptions.RequestException as e:
            messages.error(request, f'Ошибка сети: {e}')
        except ValueError as e:
            messages.error(request, f'Ошибка разбора ответа: {e}')

    return render(request, 'registration.html')


class CustomLogoutView(LogoutView):
    def get_next_page(self):
        return reverse('enter')


class UserListCreate(generics.ListCreateAPIView):
    queryset = User.objects.all()
    serializer_class = UserSerializer