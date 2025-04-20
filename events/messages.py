from django.contrib import messages
from django.shortcuts import redirect


def create_event(request):
    if request.method == "POST":

        messages.success(request, f'Ваше мероприятие "{event.title}" успешно создано.')

        return redirect('profile')