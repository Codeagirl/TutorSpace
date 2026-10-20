document.querySelectorAll('time.local').forEach(function (el) {
    var date = new Date(parseInt(el.dataset.ts) * 1000);
    el.textContent = date.toLocaleString([], { weekday: 'short', month: 'short', day: 'numeric', hour: 'numeric', minute: '2-digit' });
});
document.querySelectorAll('form').forEach(function (form) {
    form.addEventListener('submit', function () {
        form.querySelectorAll('input[data-epoch]').forEach(function (input) {
            var hidden = form.querySelector('input[name="' + input.dataset.epoch + '"]');
            hidden.value = input.value ? Math.floor(new Date(input.value).getTime() / 1000) : '';
        });
    });
});
