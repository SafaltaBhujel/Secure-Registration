document.addEventListener('DOMContentLoaded', () => {
  const passwordInput = document.getElementById('password');
  const strengthBar = document.getElementById('strength-bar');
  const bar = strengthBar.querySelector('div');

  passwordInput.addEventListener('input', () => {
    const val = passwordInput.value;
    let strength = 0;

    if (val.length >= 8) strength++;
    if (/[A-Z]/.test(val)) strength++;
    if (/[0-9]/.test(val)) strength++;
    if (/[^A-Za-z0-9]/.test(val)) strength++;

    bar.style.width = (strength * 25) + '%';

    switch (strength) {
      case 0:
      case 1:
        bar.style.backgroundColor = '#ff4d4d'; // red
        break;
      case 2:
        bar.style.backgroundColor = '#ff9933'; // orange
        break;
      case 3:
        bar.style.backgroundColor = '#ffff66'; // yellow
        break;
      case 4:
        bar.style.backgroundColor = '#66cc66'; // green
        break;
    }
  });
});
<script src="https://www.google.com/recaptcha/api.js?render={{ site_key }}"></script>
<script>
  document.querySelector('form').addEventListener('submit', function(event) {
    event.preventDefault();

    grecaptcha.ready(function() {
      grecaptcha.execute('{{ site_key }}', {action: 'login'}).then(function(token) {
        document.getElementById('g-recaptcha-response').value = token;
        event.target.submit();
      });
    });
  });
</script>

<script>
  document.addEventListener('DOMContentLoaded', () => {
    const form = document.querySelector('form');
    const submitBtn = form.querySelector('button[type="submit"]');

    form.addEventListener('submit', event => {
      event.preventDefault();
      submitBtn.disabled = true;

      grecaptcha.ready(() => {
        grecaptcha.execute('{{ site_key }}', { action: 'login' }).then(token => {
          document.getElementById('g-recaptcha-response').value = token;
          form.submit();
        }).catch(() => {
          alert('reCAPTCHA failed.');
          submitBtn.disabled = false;
        });
      });
    });
  });
</script>
