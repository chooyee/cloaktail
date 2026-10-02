// Apps that start sign-in with RelayState=signup (SAML HTTP-Redirect binding) go straight to
// registration. The page's own Register link carries this browser's sign-in session.
document.addEventListener('DOMContentLoaded', function () {
  if (new URLSearchParams(location.search).get('RelayState') !== 'signup') return;
  var register = document.querySelector('a[href*="/login-actions/registration"]');
  if (register) location.replace(register.href);
});
