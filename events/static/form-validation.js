document.getElementById('loginForm').addEventListener('submit', function(event) {
    const username = document.getElementById('username');
    const password = document.getElementById('password');
    const errorMessages = document.getElementById('errorMessages');

    errorMessages.innerHTML = '';
    let isValid = true;

    if (username.value.trim() === '') {
        isValid = false;
        showError('Пожалуйста, введите логин.');
    }

    if (password.value.trim() === '') {
        isValid = false;
        showError('Пожалуйста, введите пароль.');
    }

    if (!isValid) {
        event.preventDefault();
    }

        if (title.value.trim() === '') {
            errorMessages.push('Название мероприятия не может быть пустым.');
        }

        // Валидация даты мероприятия
        if (date.value === '') {
            errorMessages.push('Дата мероприятия не может быть пустой.');
        }

        // Валидация описания мероприятия
        if (description.value.trim() === '') {
            errorMessages.push('Описание мероприятия не может быть пустым.');
        }

        // Валидация выбора изображения
        if (image.files.length === 0) {
            errorMessages.push('Пожалуйста, выберите изображение.');
        }

        // Валидация описания фото
        if (photoDescription.value.trim() === '') {
            errorMessages.push('Описание фото не может быть пустым.');
        }

        // Выводим ошибки, если они есть
        if (errorMessages.length > 0) {
            event.preventDefault(); // Отменяем отправку формы
            showErrors(errorMessages);
        }

        function showErrors(messages) {
            const errorContainer = document.createElement('div');
            errorContainer.className = 'alert alert-danger'; // Добавляем стиль Bootstrap для ошибок

            messages.forEach(function (message) {
                const div = document.createElement('div');
                div.textContent = message;
                errorContainer.appendChild(div);
            });

            document.querySelector('.card-body').insertBefore(errorContainer, document.querySelector('form'));
        }

        function clearErrors() {
            const errorContainers = document.querySelectorAll('.alert-danger');
            errorContainers.forEach(container => container.remove());
        }
    });
});